### Build pre-reqs

- Golang version 1.21
- Cgo compilation

### Build web replay

```
.\build.ps1 web_replay
```

### Build archive editor

```
.\build.ps1 archive
```

### Using archive editor

Use the following command to merge multiple archives. Designate
one as the base, and one as input

```
bin\archive.exe merge <base_file> <input_file> <output_file>
```
