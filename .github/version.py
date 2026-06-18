import pefile, sys
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
for fi in pe.FileInfo[0]:
    if fi.Key == b'StringFileInfo':
        for st in fi.StringTable:
            v = st.entries.get(b'FileVersion', b'').decode().strip()
            if v:
                print(v)
                raise SystemExit(0)
raise SystemExit(1)
