# bloxguard

**Check your Roblox game for backdoors.**

Free models, plugins and old places sometimes hide a backdoor: a script that lets someone else run their own code in your game, or sends your game's data to them. bloxguard reads every script in your game file and points out the ones that use the tricks backdoors use. It runs on your own computer, never runs the scripts it reads, and never goes online.

This is a first test version (0.1.0-rc.1). If it flags something that is clearly normal code, or misses a backdoor, please [tell us](#found-a-problem).

## Check your game on Windows

1. **Save your game as a file.** Open your game in Roblox Studio, open the **File** menu and choose **Download a Copy** (below **Publish to Roblox As**). For a game you never published, choose **Save to File** instead. Save the `.rbxl` file somewhere you can find it, such as your Desktop. This only saves a copy: your live game stays as it is.
2. **Download bloxguard.** On the [releases page](https://github.com/waltuov/bloxguard/releases), download `bloxguard-0.1.0-rc.1-windows-x86_64.zip`. Right click the downloaded file and choose **Extract All**.
3. **Drag your `.rbxl` file onto `bloxguard.exe`** in the extracted folder. A window opens and lists what it found. Read it, then press Enter to close it.

The first time, Windows may show "Windows protected your PC", because bloxguard is new and its download is not signed. Click **More info**, then **Run anyway**. You can read every line of its code on this page first.

## Check your game on a Mac

1. **Save your game as a file**, as in step 1 above.
2. **Download bloxguard.** On the [releases page](https://github.com/waltuov/bloxguard/releases), download `bloxguard-0.1.0-rc.1-macos-aarch64.zip` for a Mac with Apple silicon (M1 or newer), or `bloxguard-0.1.0-rc.1-macos-x86_64.zip` for an Intel Mac. Double click it to unzip it.
3. **Open Terminal** (press Command and Space, type Terminal, press Return).
4. **Allow the download once.** Type `xattr -d com.apple.quarantine ` (with a space at the end), drag the `bloxguard` file into the Terminal window, and press Return. macOS blocks new downloads that are not signed until you do this.
5. **Scan.** Drag the `bloxguard` file into the Terminal window again, type ` scan ` (with a space before and after), drag your `.rbxl` file into the window, and press Return.

## What to do with the results

Here is what bloxguard shows for a test place with a backdoored free car kit in it. All names and IDs are fake. On Windows, the window also says "Press Enter to close this window" at the end.

```text
bloxguard 0.1.0-rc.1 scan: complete

.\MyGame.rbxlx [complete]
  6 instances, 2 scripts
  [high, high confidence] BG001 module is loaded from a numeric asset ID
    /Workspace/FAKE_FreeCarKit/Weld (script line 10:304)
    evidence: getfenv()[string.reverse("eriuqer")](999000000004242) [resolved asset id: 999000000004242]
    fingerprint: 55304fee5cf856d665a19881b0a7967754322ff64aa0e2984f040fc2b3d9c824
  [high, high confidence] BG004 script accesses or changes a runtime environment
    /Workspace/FAKE_FreeCarKit/Weld (script line 10:304)
    evidence: getfenv()
    fingerprint: 96a37db1f38054e9cdd629d0a7fef9a95275f3ccb5b1aff6c932bc196e425eb8

2 findings: 0 critical, 2 high, 0 medium, 0 low

Some findings meet the high threshold. Open the game in Studio, find each script by the path shown above, and remove it unless you know why it is there. See https://github.com/waltuov/bloxguard#what-to-do-with-the-results
```

The weld script in this kit looks normal, but line 10 hides `getfenv()[string.reverse("eriuqer")](999000000004242)` behind 300 spaces. That spells `require` backwards, so it loads someone else's module by its asset ID.

Each finding starts with how serious it is:

- **critical** or **high**: the script does something backdoors do, such as loading code from an asset ID, running code made from text, or sending data to a Discord webhook. Look at these first.
- **medium**: worth a look. Purchase prompts or teleports inside a model, scripts hidden in odd places, packages that can update themselves, scrambled code.
- **low**: usually fine. bloxguard saw something it could not fully check.

The confidence after it says how sure bloxguard is that it read the code right. The `evidence` line is the exact code it found. You can ignore the `fingerprint` line: it is an ID for the finding, used by CI setups.

For each high or critical finding:

1. Open your game in Studio and find the script. The path shows where it is: `/Workspace/FAKE_FreeCarKit/Weld` is the script `Weld` inside the model `FAKE_FreeCarKit` in Workspace.
2. Open the script and go to the line shown. `script line 10:304` means line 10, 304 characters from the left. Code pushed far to the right behind spaces is a common trick, so scroll right if the line looks empty.
3. If you don't know why it is there, delete it. A backdoor usually comes with a free model, so delete the whole model, then scan again.
4. Report the model on its Creator Store page with **Report Item**. Please don't accuse its creator in public: a finding is a reason to look, not proof.

Some findings are normal. Your own analytics that sends `UserId` to your own server, admin systems loaded by an asset ID you trust, test tools and plugins that run code on purpose all look like backdoor tricks. If you know why a finding is there, it is fine to keep it.

If the result says **partial**, bloxguard could not read part of your game, so the result is not complete and not clean. If that happens on a normal game, please [tell us](#found-a-problem).

A clean result is good news, but not a guarantee: see [what it can't see](#what-it-cant-see).

## Is it safe to run?

- **Open source** under MIT or Apache 2.0. Anyone can read the code.
- **Offline.** It makes no network requests.
- **Never runs the scripts it reads.** It only reads them as text and data.
- **Never changes your files.** It only reads them.
- **Same result every time** for the same file.

## What it looks for

- A `require` of an asset ID, also when the ID is hidden in strings, math, or a renamed `require` (BG001).
- A module ID stored in a value object such as an `IntValue`, or in an attribute (BG002).
- `loadstring`, such as `loadstring(game:HttpGet(url))()`, and other code made from text (BG003).
- `getfenv` and `setfenv` tricks (BG004).
- Scrambled code: long encoded strings, number escapes, `string.char` builders (BG005).
- Scripts hidden deep inside parts or in places that usually hold no code, and names that imitate Roblox objects, such as `Workspace` spelled with a look-alike letter (BG006).
- Loading assets while the game runs, such as `InsertService:LoadAsset` (BG007).
- Sending data to webhooks or sending player and server data such as `UserId` or `JobId` (BG008).
- Code that only acts outside Studio, for the owner, or after a delay, so it stays quiet while you test (BG009).
- Purchase prompts and teleports started by scripts inside models (BG010).
- Package links that can pull in updates from outside your game (BG011).
- Text that tells you to paste code into the command bar (BG012).

Each rule has its own page in [docs/rules](docs/rules), and `bloxguard explain BG001` prints the same help.

## What it can't see

- **Code that only exists while the game runs.** A backdoor can download its real code later. bloxguard flags the download (`require` of an ID, `loadstring`, `LoadAsset`, HTTP), but it can't see what would be downloaded.
- **Backdoors with no telltale code.** A "clone virus" that only copies itself into every part has no tricks to find.
- **Values passed between scripts.** Each script is read on its own, so an ID handed over through `_G` or another script gets a lower confidence finding.
- **Normal code that looks like a trick**, as described above.

The full list is in [Known limits](docs/limits.md).

## More ways to use it

- **Command line.** `bloxguard scan MyGame.rbxl`, or `bloxguard scan .` inside a Rojo project folder. Commands, JSON and SARIF output and exit codes are in [Command line](docs/cli.md).
- **GitHub Actions.** Scan every push and see the findings in GitHub's code scanning. See [GitHub Actions](docs/github-action.md).
- **AI agents.** Claude Code, Cursor and other agents can call bloxguard as an MCP tool, for example to scan a model before inserting it. See [MCP server](docs/mcp.md).
- **Configuration and baselines.** Trusted IDs, exceptions with a reason, and reporting only new findings in CI. See [Configuration](docs/configuration.md).

## Found a problem?

- **A false alarm or a missed backdoor:** [open an issue](https://github.com/waltuov/bloxguard/issues). Paste the finding and the few lines of code around it. Never upload a working backdoor or a real infected model: describe it, or replace its IDs and URLs with fake ones.
- **A way to hide a backdoor from bloxguard:** report it privately, as described in [SECURITY.md](SECURITY.md).

To build bloxguard yourself or change it, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

bloxguard is not affiliated with Roblox Corporation.
