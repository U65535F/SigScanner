project(
    'SigScanner', 
    'c',
    default_options: [
        'warning_level=3',
        'c_std=c11',
        'buildtype=release',
        'strip=true' 
    ]
)

sources = files(
    'src/Error.c',
    'src/Main.c',
    'src/Pdb.c',
    'src/Signature.c'
)

executable(
    'SigScanner', 
    sources,
    include_directories: include_directories('src/')
)
