"""
IDA Pro integration for deep driver analysis.

This module can be run as an IDA Python script or used via the IDA MCP server
for automated analysis.

Features:
- Extract IOCTL dispatch handlers
- Analyze IOCTL code handling (switch/case patterns)
- Identify dangerous API calls in each handler
- Map input buffer usage for exploitation
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class IOCTLHandler:
    """Information about an IOCTL handler."""

    code: int
    handler_addr: int
    handler_name: Optional[str]
    calls_dangerous_apis: List[str]
    uses_input_buffer: bool
    uses_output_buffer: bool
    input_buffer_offset: Optional[int]
    size_from_input: bool


@dataclass
class DriverAnalysis:
    """Full driver analysis result from IDA."""

    driver_entry: int
    device_control_handler: Optional[int]
    device_names: List[str]
    ioctl_handlers: List[IOCTLHandler]
    dangerous_functions: List[Tuple[int, str]]
    strings: List[Tuple[int, str]]


# Dangerous kernel APIs to look for
DANGEROUS_KERNEL_APIS = {
    # Physical memory
    "MmMapIoSpace",
    "MmMapIoSpaceEx",
    "MmUnmapIoSpace",
    "MmGetPhysicalAddress",
    "MmAllocateContiguousMemory",
    "MmAllocateContiguousMemorySpecifyCache",
    # Section mapping
    "ZwMapViewOfSection",
    "ZwOpenSection",
    "MmMapLockedPages",
    "MmMapLockedPagesSpecifyCache",
    # Registry (for persistence)
    "ZwSetValueKey",
    "ZwCreateKey",
    # Process/Thread manipulation
    "ZwOpenProcess",
    "ZwReadVirtualMemory",
    "ZwWriteVirtualMemory",
    "MmCopyVirtualMemory",
    "KeStackAttachProcess",
    # Object manipulation
    "ObOpenObjectByPointer",
    "ObReferenceObjectByHandle",
    # HAL
    "HalGetBusData",
    "HalGetBusDataByOffset",
    "HalSetBusData",
    "HalSetBusDataByOffset",
}


def is_ida_available() -> bool:
    """Check if running inside IDA."""
    try:
        import idaapi

        return True
    except ImportError:
        return False


if is_ida_available():
    import idaapi
    import idautils
    import idc

    def find_driver_entry() -> Optional[int]:
        """Find the DriverEntry function."""
        # Look for export
        for ea, name in idautils.Names():
            if name in ("DriverEntry", "GsDriverEntry", "_DriverEntry@8"):
                return ea

        # Look for typical DriverEntry pattern at entry point
        entry = idaapi.get_inf_structure().start_ea
        if entry:
            return entry

        return None

    def find_device_control_handler(driver_entry: int) -> Optional[int]:
        """
        Find IRP_MJ_DEVICE_CONTROL handler by analyzing DriverEntry.

        Looks for pattern:
          DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = handler
          (DriverObject offset 0x70, IRP_MJ_DEVICE_CONTROL = 14)
        """
        # IRP_MJ_DEVICE_CONTROL = 14, offset in MajorFunction array = 14*8 = 0x70
        # DriverObject->MajorFunction is at offset 0x70 from DriverObject
        # So we look for writes to [reg+0x70+14*8] = [reg+0xE0]

        func = idaapi.get_func(driver_entry)
        if not func:
            return None

        # Scan function for MajorFunction assignment
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head)
            if mnem != "mov":
                continue

            # Check if destination is [something+0xE0]
            op1 = idc.print_operand(head, 0)
            if "+0E0h]" in op1 or "+70h]" in op1:
                # Get the source operand (handler address)
                op2_type = idc.get_operand_type(head, 1)
                if op2_type in (idc.o_imm, idc.o_mem):
                    handler = idc.get_operand_value(head, 1)
                    if idaapi.is_func(idaapi.get_flags(handler)):
                        return handler

        return None

    def analyze_ioctl_dispatch(handler_addr: int) -> List[IOCTLHandler]:
        """
        Analyze IOCTL dispatch function for handled codes.

        Looks for switch/case patterns on IoControlCode.
        """
        handlers = []
        func = idaapi.get_func(handler_addr)
        if not func:
            return handlers

        # Look for comparisons that might be IOCTL codes
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head)

            if mnem == "cmp":
                # Get the immediate value being compared
                op2_type = idc.get_operand_type(head, 1)
                if op2_type == idc.o_imm:
                    value = idc.get_operand_value(head, 1)

                    # Check if it looks like an IOCTL code
                    device_type = (value >> 16) & 0xFFFF
                    if device_type >= 0x22:  # FILE_DEVICE_UNKNOWN or higher
                        handlers.append(
                            IOCTLHandler(
                                code=value,
                                handler_addr=head,
                                handler_name=None,
                                calls_dangerous_apis=[],
                                uses_input_buffer=False,
                                uses_output_buffer=False,
                                input_buffer_offset=None,
                                size_from_input=False,
                            )
                        )

            elif mnem == "sub":
                # Switch tables sometimes use subtraction
                op2_type = idc.get_operand_type(head, 1)
                if op2_type == idc.o_imm:
                    value = idc.get_operand_value(head, 1)
                    device_type = (value >> 16) & 0xFFFF
                    if device_type >= 0x22:
                        handlers.append(
                            IOCTLHandler(
                                code=value,
                                handler_addr=head,
                                handler_name=None,
                                calls_dangerous_apis=[],
                                uses_input_buffer=False,
                                uses_output_buffer=False,
                                input_buffer_offset=None,
                                size_from_input=False,
                            )
                        )

        return handlers

    def find_dangerous_calls(start_ea: int, end_ea: int) -> List[Tuple[int, str]]:
        """Find calls to dangerous APIs within a range."""
        results = []

        for head in idautils.Heads(start_ea, end_ea):
            if idc.print_insn_mnem(head) != "call":
                continue

            # Get call target
            op_type = idc.get_operand_type(head, 0)
            if op_type in (idc.o_near, idc.o_far, idc.o_mem):
                target = idc.get_operand_value(head, 0)
                name = idc.get_name(target)
                if name in DANGEROUS_KERNEL_APIS:
                    results.append((head, name))

        return results

    def analyze_driver() -> DriverAnalysis:
        """Perform full driver analysis."""
        driver_entry = find_driver_entry()
        device_control = None
        ioctl_handlers = []
        dangerous_funcs = []
        device_names = []

        if driver_entry:
            device_control = find_device_control_handler(driver_entry)

            if device_control:
                ioctl_handlers = analyze_ioctl_dispatch(device_control)

            # Find dangerous calls in entire binary
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if seg and seg.perm & idaapi.SEGPERM_EXEC:
                    dangerous_funcs.extend(
                        find_dangerous_calls(seg.start_ea, seg.end_ea)
                    )

        # Extract device name strings
        for ea, name in idautils.Names():
            if "\\Device\\" in name or "\\DosDevices\\" in name:
                device_names.append(name)

        # Also check strings
        strings = []
        for s in idautils.Strings():
            str_val = str(s)
            if "\\Device\\" in str_val or "\\DosDevices\\" in str_val:
                device_names.append(str_val)
                strings.append((s.ea, str_val))

        return DriverAnalysis(
            driver_entry=driver_entry or 0,
            device_control_handler=device_control,
            device_names=device_names,
            ioctl_handlers=ioctl_handlers,
            dangerous_functions=dangerous_funcs,
            strings=strings,
        )

    def run_analysis_script():
        """Run when executed as IDA script."""
        print("=" * 60)
        print("BYOVD Scanner - IDA Analysis")
        print("=" * 60)

        analysis = analyze_driver()

        print(f"\nDriverEntry: 0x{analysis.driver_entry:X}")
        print(f"DeviceControl Handler: 0x{analysis.device_control_handler:X}" if analysis.device_control_handler else "DeviceControl Handler: Not found")

        if analysis.device_names:
            print(f"\nDevice Names ({len(analysis.device_names)}):")
            for name in analysis.device_names:
                print(f"  - {name}")

        if analysis.ioctl_handlers:
            print(f"\nIOCTL Handlers ({len(analysis.ioctl_handlers)}):")
            for h in analysis.ioctl_handlers:
                print(f"  - 0x{h.code:08X} @ 0x{h.handler_addr:X}")

        if analysis.dangerous_functions:
            print(f"\nDangerous API Calls ({len(analysis.dangerous_functions)}):")
            for addr, name in analysis.dangerous_functions:
                print(f"  - 0x{addr:X}: {name}")

        return analysis

    # Auto-run if executed as script
    if __name__ == "__main__":
        run_analysis_script()

else:
    # Stub implementations when not in IDA
    def find_driver_entry() -> Optional[int]:
        raise RuntimeError("IDA Pro not available")

    def find_device_control_handler(driver_entry: int) -> Optional[int]:
        raise RuntimeError("IDA Pro not available")

    def analyze_ioctl_dispatch(handler_addr: int) -> List[IOCTLHandler]:
        raise RuntimeError("IDA Pro not available")

    def find_dangerous_calls(start_ea: int, end_ea: int) -> List[Tuple[int, str]]:
        raise RuntimeError("IDA Pro not available")

    def analyze_driver() -> DriverAnalysis:
        raise RuntimeError("IDA Pro not available")

    def run_analysis_script():
        raise RuntimeError("IDA Pro not available")
