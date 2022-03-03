
IMAGE_IMPORT_DESCRIPTOR STRUCT
	union 
        Characteristics dd      ?
        OriginalFirstThunk dd   ?
    ends
    TimeDateStamp dd    ?
    ForwarderChain dd   ?
    Name dd             ?
    FirstThunk dd       ?
IMAGE_IMPORT_DESCRIPTOR ENDS

IMAGE_THUNK_DATA64 STRUCT
    union u1
        ForwarderString dq  ?
        Function dq	        ?
        Ordinal dq          ?
        AddressOfData dq    ?
    ends
IMAGE_THUNK_DATA64 ENDS

IMAGE_IMPORT_BY_NAME STRUCT
    Hint dw     ?
    Name1 db    ?
IMAGE_IMPORT_BY_NAME ENDS  

IMAGE_TLS_DIRECTORY32 STRUCT
    StartAddressOfRawData dd    ?
    EndAddressOfRawData dd      ?
    AddressOfIndex dd           ?
    AddressOfCallBacks dd       ?
    SizeOfZeroFill dd           ?
    Characteristics dd          ?
IMAGE_TLS_DIRECTORY32 ENDS

PAGE_EXECUTE_READWRITE equ 40h

IMAGE_BASE_RELOCATION STRUCT
    VirtualAddress dd   ?
    SizeOfBlock dd      ?
IMAGE_BASE_RELOCATION ENDS

IMAGE_REL_BASED_ABSOLUTE equ 0
IMAGE_REL_BASED_HIGH equ 1
IMAGE_REL_BASED_LOW equ 2
IMAGE_REL_BASED_HIGHLOW equ 3