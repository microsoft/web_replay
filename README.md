# Web Replay
Web Replay is a performance testing tool written in Golang for
recording and replaying web pages. Originally based on [Catapult > Web Page Replay](https://chromium.googlesource.com/catapult).

## Sample Usage

### Certificate installation

In order for the web_replay server (on **HOST PC**) to be trusted by the browser (on Device Under Test, **DUT**), the certificates generated
and used by web_replay must be added to the trusted certificate store on the DUT. Multiple options are possible to support this:

#### Browser Parameter

Specify public key hashes for the browser to ignore using `--ignore-certificate-errors-spki-list`.
Run `utils\create_pk_hash.sh <cert>` to output the hash to include. The following ignores the included
two leaf certificates:

```
--ignore-certificate-errors-spki-list=2FBkVuYq8NvFRbHkFRFnXLd/FJK5tu7m/b+V7s/TUL4=,P0/jlVD2vgAtt9UmEeZf7IrHAva3Fs8N+4V9glmvwkc=
```

#### Certificate Store

Install the certificate chain on a test machine (**DUT**) using `install_certs.ps1`. **Use this with care as installing a root CA compromises your machine**.

The certificates listed in `.\certs` are used by default. These can be modified by replacing the
chain with a different one.

### Point browser to web_replay

Modify the host resolver rules of the browser on **DUT** by using `--host-resolver-rules`:
```
--host-resolver-rules="MAP *:80 <host>:<http_port>,MAP *:443 <host>:<https_port>"
```

For example:
```
--host-resolver-rules="MAP *:80 192.168.31.16:80,MAP *:443 192.168.31.16:8443"
```

`set_args.ps1` and `remove_args.ps1` are PowerShell scripts that handle setting and removing browser arguments for the specified browser located on the taskbar of DUT. 
`set_args.ps1` modifies the browser shortcut to include the specified arguments, while `remove_args.ps1` restores the shortcut to its original state. Use them in the following way:
```
.\set_args.ps1 web_replay <host> <http_port> <https_port> <browser>
```

For example:
```
.\set_args.ps1 web_replay 192.168.31.16 80 8443 edge
```

```
.\remove_args.ps1 <browser>
```

`<browser>` is optional and is one of (default is `edge`):

```
edge
edgedev
edgebeta
edgecanary
chrome
```

Another method for pointing the browser on DUT to web_replay is by configuring proxy settings. This can
be done within the browser settings itself, using the browser parameter `--proxy-server`, or within
system settings.

**Note: it may be necessary to terminate all the browser processes before launching for the
command-line parameters to be included.**

### Record an archive

**Standard method:**

> [!NOTE]
> Please run the command from the `web_replay` folder instead of under the **bin** folder. Running `web_replay.exe` directly from the bin folder may cause errors.

```
.\bin\web_replay.exe record --host=<host> --http_port=<http_port> --https_port=<https_port> <archive>
```

For example:
```
.\bin\web_replay.exe record --host=192.168.31.16 --http_port=8080 --https_port=8443 c:\temp\archive
```
> [!NOTE]
> Please run the command from web_replay folder instead of under **bin** folder. Run web_replay.exe under bin folder directly may cause errors.

**Proxy method:**

```
.\bin\web_replay.exe record --host=<host> --http_proxy_port=<http_proxy_port> <archive>
```


`<archive>` is either a single file or a folder.
> One HOST PC can record only one DUT at a time. To record on multiple DUTs simultaneously, you must run separate instances of web_replay on different HOST PCs, with each DUT pointing to its respective HOST PC.
> One HOST PC can record only one DUT at a time. If you want to record on multiple DUTs, you need to run
> Record multiple instances of web_replay on different HOST PCs. Each DUT must be pointed to its own HOST PC.


### Replay an archive

**Standard method:**

```
.\bin\web_replay.exe replay --host=<host> --http_port=<http_port> --https_port=<https_port> <archive>
```
For example:
```
.\bin\web_replay.exe replay --host=192.168.31.16 --http_port=8080 --https_port=8443 c:\temp\archive
```
> [!NOTE]
> Please run the command from web_replay folder instead of under **bin** folder. Run web_replay.exe under bin folder directly may cause errors.


**Proxy method:**

```
.\bin\web_replay.exe replay --host=<host> --http_proxy_port=<http_proxy_port> <archive>
```

`<archive>` is either a single file or a folder.

The optional parameter `--excludes_list` accepts a space-separated list of domains for
which web_replay will always fetch data from the live internet.

### Special URL Paths

The following table includes some common special URL paths that perform custom web_replay actions
during a recording or replay:

| Path                                  | Details                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------- |
| /web-page-replay-generate-200         | Generate a 200 ok response                                                      |
| /web-page-replay-command-exit         | Shutdown web_replay server                                                      |
| /web-page-replay-change-archive?n={n} | Change active archive file. {n} is the archive file without the .json.gz suffix |

### Using archive editor

Use the following command to merge multiple archives. Designate
one as the base, and one as input:

```
.\bin\archive.exe merge <base_file> <input_file> <output_file>
```

## Building

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

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
