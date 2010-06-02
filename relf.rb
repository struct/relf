#!/usr/bin/env ruby

## Ruckus structures and methods for parsing ELF
##
## You can get ruckus at http://github.com/tqbf/ruckus
##
## Properties:
##
##  ehdr - a ruckus structure holding the ELF header
##  phdr - an array of ruckus structures holding each Program header
##  shdr - an array of ruckus structures holding each Section header
##  dyn  - an array of ruckus structures holding each dynamic table entry
##  symbols - an array of ruckus structures holding each symbol table entry
##
## Methods:
##
##  parse_ehdr - stores the Elf header in the RELF::ehdr ruckus structure
##  parse_phdr - stores an array of ruckus structures containing the Phdr in RELF::phdr
##  parse_shdr - stores an array of ruckus structures containing the Shdr in RELF::shdr
##  parse_dyn - stores an array of ruckus structures containing the Dyn in RELF::dyn
##  parse_symbols - returns an array of ruckus structures containing the symbol table
##
## TODO:
##  - extend the ruckus structures themselves instead of 'get_shdr_name' methods
##  - Methods between ruPE and rELF should be uniform and
##    have similar return values (arrays vs strings vs ruckus structures)
##  - Parse more ELF structures (relocations etc...)

require 'ruckus'

class RELF

    attr_accessor :dat, :ehdr, :phdr, :shdr, :dyn, :strtab, :hash, :gnu_hash, :dynsym, :symtab, :syment, :symbols

    def initialize(elf_file)
        begin   
            @elf_file = elf_file
            @dat = File.read(elf_file)
        rescue
            puts "Could not read [ #{elf_file} ]"
            exit
        end

        @phdr = Array.new
        @shdr = Array.new
        @dyn  = Array.new
        @symbols = Array.new

        parse_ehdr
        parse_phdr
        parse_dyn
        parse_shdr
    end

    def get_file
        @dat.dup
    end

    def parse_ehdr
        @ehdr = ELFHeader.new
        ehdr.capture(get_file)
    end

    def parse_phdr
        0.upto(ehdr.e_phnum.to_i-1) do |j|
            p = ELFProgramHeader.new
            f = get_file
            p.capture f[ehdr.e_phoff.to_i + (ehdr.e_phentsize.to_i * j), ehdr.e_phentsize.to_i]
            phdr.push(p)
        end
    end

    def get_phdr(type)
        phdr.each do |p|
            if p.p_type.to_i == type
                return p
            end
        end
    end

    def get_phdr_name(phdr)
        case phdr.p_type.to_i
            when PhdrTypes::PT_NULL
                return "PT_NULL"
            when PhdrTypes::PT_LOAD
                return "PT_NULL"
            when PhdrTypes::PT_DYNAMIC
                return "PT_DYNAMIC"
            when PhdrTypes::PT_INTERP
                return "PT_INTERP"
            when PhdrTypes::PT_NOTE
                return "PT_NOTE"
            when PhdrTypes::PT_SHLIB
                return "PT_SHLIB"
            when PhdrTypes::PT_PHDR
                return "PT_PHDR"
            when PhdrTypes::PT_TLS
                return "PT_TLS"
            when PhdrTypes::PT_NUM
                return "PT_NUM"
            when PhdrTypes::PT_LOOS
                return "PT_LOOS"
            when PhdrTypes::PT_GNU_EH_FRAME
                return "PT_GNU_EH_FRAME"
            when PhdrTypes::PT_GNU_STACK
                return "PT_GNU_STACK"
            when PhdrTypes::PT_GNU_RELRO
                return "PT_GNU_RELRO"
            when PhdrTypes::PT_LOSUNW
                return "PT_LOSUNW"
            when PhdrTypes::PT_SUNWSTACK
                return "PT_SUNWSTACK"
            when PhdrTypes::PT_HIOS
                return "PT_HIOS"
            when PhdrTypes::PT_LOPROC
                return "PT_LOPROC"
            when PhdrTypes::PT_HIPROC
                return "PT_HIPROC"
        end
    end

    def parse_shdr
        0.upto(ehdr.e_shnum.to_i-1) do |j|
            s = ELFSectionHeader.new
            f = get_file
            s.capture(f[ehdr.e_shoff.to_i + (ehdr.e_shentsize.to_i * j), ehdr.e_shentsize.to_i])

            if s.sh_type.to_i == ShdrTypes::SHT_STRTAB
                @shstrtab = ELFSectionHeader.new
                shstrtab = s
            end

            shdr.push(s)
        end
    end

    def get_shdr(type)
        shdr.each do |s|
            if s.sh_type.to_i == type
                return s
            end
        end
    end

    def get_shdr_name(shdr)
        f = get_file

        if dyn.size == 0
            parse_dyn
        end

        str = f[@shstrtab.sh_offset.to_i + shdr.sh_name.to_i, 256]
        str = str[0, str.index("\x00")]
    end

    def parse_dyn
        p = get_phdr(PhdrTypes::PT_DYNAMIC)
        dynamic_section_offset = p.p_vaddr.to_i

        d = ELFDynamic.new
        @strtab = ELFSectionHeader.new
        @hash = ELFSectionHeader.new
        @gnu_hash = ELFSectionHeader.new
        @dynsym = ELFSectionHeader.new
        @syment = 0

        0.upto(p.p_filesz.to_i / d.size.to_i) do |j|
            d = ELFDynamic.new
            f = get_file
            d.capture(f[p.p_offset.to_i + (d.size.to_i * j), d.size.to_i])

            if d.d_tag.to_i == DynamicTypes::DT_NULL
                break
            end

              case d.d_tag.to_i
                    when DynamicTypes::DT_STRTAB
                    if ehdr.e_type.to_i == ELFTypes::ET_EXEC
                        strtab.sh_offset = d.d_val.to_i - BASEADDR
                    end
                    if ehdr.e_type.to_i == ELFTypes::ET_DYN
                        strtab.sh_offset = d.d_val.to_i
                    end
                when DynamicTypes::DT_SYMENT
                    @syment = d.d_val.to_i

                when DynamicTypes::DT_HASH
                    if ehdr.e_type.to_i == ELFTypes::ET_EXEC
                        hash.sh_offset = d.d_val.to_i - BASEADDR
                    end
                    if ehdr.e_type.to_i == ELFTypes::ET_DYN
                        hash.sh_offset = d.d_val.to_i
                    end

                when DynamicTypes::DT_GNU_HASH
                    if ehdr.e_type.to_i == ELFTypes::ET_EXEC
                        gnu_hash.sh_offset = d.d_val.to_i - BASEADDR
                    end
                    if ehdr.e_type.to_i == ELFTypes::ET_DYN
                        gnu_hash.sh_offset = d.d_val.to_i
                    end
                when DynamicTypes::DT_SYMTAB
                    if ehdr.e_type.to_i == ELFTypes::ET_EXEC
                        dynsym.sh_offset = d.d_val.to_i - BASEADDR
                    end
                    if ehdr.e_type.to_i == ELFTypes::ET_DYN
                        dynsym.sh_offset = d.d_val.to_i
                    end
            end # case statement

            dyn.push(d)
        end
    end

    def get_dyn(type)
        dyn.each do |d|
            if d.d_tag.to_i == type
                return d
            end
        end
    end

    def parse_dynsym
        d = get_shdr(ShdrTypes::SHT_DYNSYM)

        if !d.kind_of? ELFSectionHeader
            d = @dynsym
        end

       num_of_symbols = (d.sh_size.to_i / @syment)
       #num_of_symbols = dat[@hash.sh_offset + 4]

        0.upto(num_of_symbols.to_i-1) do |j|
            sym = ELFSymbol.new
            f = get_file
            sym.capture(f[d.sh_offset.to_i + (j * sym.size), sym.size])
            f = get_file
            str = f[strtab.sh_offset.to_i + sym.st_name.to_i, 256]

            if block_given?
                yield(sym)
            end

            symbols.push(sym)
        end
    end

    def parse_symtab
        @symtab = get_shdr(ShdrTypes::SHT_SYMTAB)

        if !@symtab.kind_of? ELFSectionHeader
            return
        end

        @sym_str_tbl = shdr[@symtab.sh_link.to_i]

        num_of_symbols = (@symtab.sh_size.to_i / @syment)
        #num_of_symbols = dat[hash.sh_offset + 4]

        0.upto(num_of_symbols.to_i-1) do |j|
            sym = ELFSymbol.new
            f = get_file
            sym.capture(f[@symtab.sh_offset.to_i + (j * sym.size), sym.size])
            f = get_file
            str = f[@sym_str_tbl.sh_offset.to_i + sym.st_name.to_i, 256]

            if block_given?
                yield(sym)
            end

            symbols.push(sym)
        end
    end

    def get_dyn_symbol_name(sym)
        f = get_file
        str = f[strtab.sh_offset.to_i + sym.st_name.to_i, 256]
        str = str[0, str.index("\x00")]
    end

    def get_sym_symbol_name(sym)
        f = get_file
        str = f[@sym_str_tbl.sh_offset.to_i + sym.st_name.to_i, 256]
        str = str[0, str.index("\x00")]
    end

    def get_symbol_bind(sym)
        case (sym.st_info.to_i >> 4)
            when SymbolBind::STB_LOCAL
                return "LOCAL"
            when SymbolBind::STB_GLOBAL
                return "GLOBAL"
            when SymbolBind::STB_WEAK
                return "WEAK"
            when SymbolBind::STB_NUM
                return "NUM"
            when SymbolBind::STB_LOOS
                return "LOOS"
            when SymbolBind::STB_HIOS
                return "HIOS"
            when SymbolBind::STB_LOPROC
                return "LOPROC"
            when SymbolBind::STB_HIPROC
                return "HIPROC"
        end
    end
    
    def get_symbol_type(sym)
        case (sym.st_info.to_i & 0xf)
            when SymbolTypes::STT_NOTYPE
                return "NOTYPE"
            when SymbolTypes::STT_OBJECT
                return "OBJECT"
            when SymbolTypes::STT_FUNC
                return "FUNC"
            when SymbolTypes::STT_SECTION
                return "SECTION"
            when SymbolTypes::STT_FILE
                return "FILE"
            when SymbolTypes::STT_COMMON
                return "COMMON"
            when SymbolTypes::STT_TLS
                return "TLS"
            when SymbolTypes::STT_NUM
                return "NUM"
            when SymbolTypes::STT_LOOS
                return "LOOS"
            when SymbolTypes::STT_HIOS
                return "HIOS"
            when SymbolTypes::STT_LOPROC
                return "LOPROC"
            when SymbolTypes::STT_HIPROC
                return "HIPROC"
        end
    end

    BASEADDR = 0x8048000    ## i386 Linux

    ## Basic ELF Header
    class ELFHeader < Ruckus::Structure
        str  :e_ident,  :in_size => 16
        Le16 :e_type
        Le16 :e_machine 
        Le32 :e_version 
        Le32 :e_entry   
        Le32 :e_phoff   
        Le32 :e_shoff   
        Le32 :e_flags   
        Le16 :e_ehsize  
        Le16 :e_phentsize 
        Le16 :e_phnum   
        Le16 :e_shentsize 
        Le16 :e_shnum   
        Le16 :e_shstrndx 
    end

    ## ELF Program Header
    class ELFProgramHeader < Ruckus::Structure
        Le32 :p_type        
        Le32 :p_offset          
        Le32 :p_vaddr           
        Le32 :p_paddr           
        Le32 :p_filesz          
        Le32 :p_memsz           
        Le32 :p_flags           
        Le32 :p_align           
    end

    ## ELF Section Header
    class ELFSectionHeader < Ruckus::Structure
        Le32 :sh_name
        Le32 :sh_type
        Le32 :sh_flags
        Le32 :sh_addr
        Le32 :sh_offset
        Le32 :sh_size
        Le32 :sh_link
        Le32 :sh_info
        Le32 :sh_addralign
        Le32 :sh_entsize
    end

    class ELFDynamic < Ruckus::Structure
        Le32 :d_tag
        Le32 :d_val
    ###     Le32 :d_ptr
    end

    class ELFSymbol < Ruckus::Structure
        Le32 :st_name   ## Symbol name (string tbl index) 
        Le32 :st_value  ## Symbol value
        Le32 :st_size   ## Symbol size 
        Le8  :st_info   ## Symbol type and binding 
        Le8  :st_other  ## Symbol visibility 
        Le16 :st_shndx  ## Section index 
    end

    class ELFRelocation < Ruckus::Structure
        Le32 :r_offset  ## Address
        Le32 :r_info    ## Type
    end

    class ELFTypes
        ET_NONE = 0         ## No file type 
        ET_REL = 1          ## Relocatable file 
        ET_EXEC = 2         ## Executable file 
        ET_DYN = 3          ## Shared object file 
        ET_CORE = 4         ## Core file 
    end

    class ShdrTypes
        SHT_NULL     = 0 ## Section header table entry unused 
        SHT_PROGBITS = 1 ## Program data 
        SHT_SYMTAB  = 2  ## Symbol table 
        SHT_STRTAB  = 3  ## String table 
        SHT_RELA    = 4  ## Relocation entries with addends 
        SHT_HASH    = 5  ## Symbol hash table 
        SHT_DYNAMIC = 6  ## Dynamic linking information 
        SHT_NOTE    = 7  ## Notes 
        SHT_NOBITS  = 8  ## Program space with no data (bss) 
        SHT_REL     = 9  ## Relocation entries, no addends 
        SHT_SHLIB   = 10 ## Reserved 
        SHT_DYNSYM  = 11 ## Dynamic linker symbol table 
        SHT_INIT_ARRAY = 14 ## Array of constructors 
        SHT_FINI_ARRAY = 15 ## Array of destructors 
        SHT_PREINIT_ARRAY = 16  ## Array of pre-constructors 
        SHT_GROUP = 17          ## Section group 
        SHT_SYMTAB_SHNDX = 18   ## Extended section indeces 
        SHT_NUM = 19            ## Number of defined types.  
        SHT_LOOS =  0x60000000          ## Start OS-specific.  
        SHT_GNU_HASH = 0x6ffffff6       ## GNU-style hash table.  
        SHT_GNU_LIBLIST = 0x6ffffff7    ## Prelink library list 
        SHT_CHECKSUM = 0x6ffffff8       ## Checksum for DSO content.  
        SHT_LOSUNW = 0x6ffffffa         ## Sun-specific low bound.  
        SHT_SUNW_move = 0x6ffffffa
        SHT_SUNW_COMDAT = 0x6ffffffb
        SHT_SUNW_syminfo = 0x6ffffffc
        SHT_GNU_verdef = 0x6ffffffd     ## Version definition section.  
        SHT_GNU_verneed = 0x6ffffffe    ## Version needs section.  
        SHT_GNU_versym = 0x6fffffff     ## Version symbol table.  
        SHT_HISUNW = 0x6fffffff         ## Sun-specific high bound.  
        SHT_HIOS = 0x6fffffff      ## End OS-specific type 
        SHT_LOPROC = 0x70000000    ## Start of processor-specific 
        SHT_HIPROC = 0x7fffffff    ## End of processor-specific 
        SHT_LOUSER = 0x80000000    ## Start of application-specific 
        SHT_HIUSER = 0x8fffffff    ## End of application-specific 
    end

    class PhdrTypes
        PT_NULL = 0     ## Program header table entry unused 
        PT_LOAD = 1     ## Loadable program segment 
        PT_DYNAMIC = 2  ## Dynamic linking information 
        PT_INTERP = 3   ## Program interpreter 
        PT_NOTE = 4     ## Auxiliary information 
        PT_SHLIB = 5    ## Reserved 
        PT_PHDR = 6     ## Entry for header table itself 
        PT_TLS = 7      ## Thread-local storage segment 
        PT_NUM = 8      ## Number of defined types 
        PT_LOOS =  0x60000000  ## Start of OS-specific 
        PT_GNU_EH_FRAME = 0x6474e550 ## GCC .eh_frame_hdr segment 
        PT_GNU_STACK = 0x6474e551    ## Indicates stack executability 
        PT_GNU_RELRO = 0x6474e552    ## Read-only after relocation 
        PT_LOSUNW = 0x6ffffffa
        PT_SUNWSTACK = 0x6ffffffb   ## Stack segment 
        PT_HIOS  = 0x6fffffff       ## End of OS-specific 
        PT_LOPROC = 0x70000000      ## Start of processor-specific 
        PT_HIPROC = 0x7fffffff      ## End of processor-specific 
    end

    class DynamicTypes
        DT_NULL     = 0       ## Marks end of dynamic section 
        DT_NEEDED   = 1       ## Name of needed library 
        DT_PLTRELSZ = 2       ## Size in Le8s of PLT relocs 
        DT_PLTGOT   = 3       ## Processor defined value 
        DT_HASH     = 4       ## Address of symbol hash table 
        DT_STRTAB   = 5       ## Address of string table 
        DT_SYMTAB   = 6       ## Address of symbol table 
        DT_RELA     = 7       ## Address of Rela relocs 
        DT_RELASZ   = 8       ## Total size of Rela relocs 
        DT_RELAENT  = 9       ## Size of one Rela reloc 
        DT_STRSZ    = 10      ## Size of string table 
        DT_SYMENT   = 11      ## Size of one symbol table entry 
        DT_INIT     = 12      ## Address of init function 
        DT_FINI     = 13      ## Address of termination function 
        DT_SONAME   = 14      ## Name of shared object 
        DT_RPATH    = 15      ## Library search path (deprecated) 
        DT_SYMBOLIC = 16      ## Start symbol search here 
        DT_REL      = 17      ## Address of Rel relocs 
        DT_RELSZ    = 18      ## Total size of Rel relocs 
        DT_RELENT   = 19      ## Size of one Rel reloc 
        DT_PLTREL   = 20      ## Type of reloc in PLT 
        DT_DEBUG    = 21      ## For debugging; unspecified 
        DT_TEXTREL  = 22      ## Reloc might modify .text 
        DT_JMPREL   = 23      ## Address of PLT relocs 
        DT_BIND_NOW = 24      ## Process relocations of object 
        DT_INIT_ARRAY   = 25  ## Array with addresses of init fct 
        DT_FINI_ARRAY   = 26  ## Array with addresses of fini fct 
        DT_INIT_ARRAYSZ = 27  ## Size in Le8s of DT_INIT_ARRAY 
        DT_FINI_ARRAYSZ = 28  ## Size in Le8s of DT_FINI_ARRAY 
        DT_RUNPATH  = 29      ## Library search path 
        DT_FLAGS    = 30      ## Flags for the object being loaded 
        DT_ENCODING = 32      ## Start of encoded range 
        DT_PREINIT_ARRAY    = 32     ## Array with addresses of preinit fct
        DT_PREINIT_ARRAYSZ  = 33     ## size in Le8s of DT_PREINIT_ARRAY 
        DT_NUM  = 34      ## Number used 
        DT_LOOS = 0x6000000d    ## Start of OS-specific 
        DT_HIOS = 0x6ffff000    ## End of OS-specific 
        DT_LOPROC = 0x70000000  ## Start of processor-specific 
        DT_HIPROC = 0x7fffffff  ## End of processor-specific 
        DT_ADDRRNGLO    = 0x6ffffe00
        DT_GNU_HASH     = 0x6ffffef5  ## GNU-style hash table.  
        DT_TLSDESC_PLT  = 0x6ffffef6
        DT_TLSDESC_GOT  = 0x6ffffef7
        DT_GNU_CONFLICT = 0x6ffffef8  ## Start of conflict section 
        DT_GNU_LIBLIST  = 0x6ffffef9  ## Library list 
        DT_CONFIG   = 0x6ffffefa  ## Configuration information.  
        DT_DEPAUDIT = 0x6ffffefb  ## Dependency auditing.  
        DT_AUDIT    = 0x6ffffefc  ## Object auditing.  
        DT_PLTPAD   = 0x6ffffefd  ## PLT padding.  
        DT_MOVETAB  = 0x6ffffefe  ## Move table.  
        DT_SYMINFO  = 0x6ffffeff  ## Syminfo table.  
        DT_ADDRRNGHI = 0x6ffffeff
    end

    class SymbolBind
        STB_LOCAL   = 0       ## Local symbol 
        STB_GLOBAL  = 1       ## Global symbol 
        STB_WEAK    = 2       ## Weak symbol 
        STB_NUM     = 3       ## Number of defined types.  
        STB_LOOS    = 10      ## Start of OS-specific 
        STB_HIOS    = 12      ## End of OS-specific 
        STB_LOPROC  = 13      ## Start of processor-specific 
        STB_HIPROC  = 15      ## End of processor-specific 
    end

    class SymbolTypes
        STT_NOTYPE  = 0       ## Symbol type is unspecified 
        STT_OBJECT  = 1       ## Symbol is a data object 
        STT_FUNC    = 2       ## Symbol is a code object 
        STT_SECTION = 3       ## Symbol associated with a section 
        STT_FILE    = 4       ## Symbol's name is file name 
        STT_COMMON  = 5       ## Symbol is a common data object 
        STT_TLS     = 6       ## Symbol is thread-local data object
        STT_NUM     = 7       ## Number of defined types.  
        STT_LOOS    = 10      ## Start of OS-specific 
        STT_HIOS    = 12      ## End of OS-specific 
        STT_LOPROC  = 13      ## Start of processor-specific 
        STT_HIPROC  = 15      ## End of processor-specific 
    end
end

## Test code
if $0 == __FILE__
    d = RELF.new(ARGV[0])

    ## The Elf header is automatically parsed
    ## at object instantiation
    puts d.ehdr.to_human

    ## The section headers (if any) are automatically
    ## parsed at object instantiation
    d.shdr.each do |s|
        puts sprintf("\n%s", d.get_shdr_name(s))
        puts s.to_human
    end

    ## The program headers are automatically
    ## parsed at object instantiation
    d.phdr.each do |p|
        puts sprintf("\n%s", d.get_phdr_name(p))
        puts p.to_human
    end

    ## The dynamic segment is automatically
    ## parsed at object instantiation
    d.dyn.each do |dyn|
        puts dyn.to_human
    end

    ## Parse and print each dynsym symbol
    d.parse_dynsym
    d.symbols.each do |sym|
        puts sprintf("%s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_dyn_symbol_name(sym));
    end

    ## The parse_symtab and parse_dynsym
    ## methods can optionally take a block
    d.parse_symtab do |sym|
        puts sprintf("%s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_sym_symbol_name(sym));
    end
end
