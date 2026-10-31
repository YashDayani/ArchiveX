# What ArchiveX can do

Everything in one place. In the app, open it any time from **Help → Features & Shortcuts**.

**Jump to:** [Open and browse](#open-and-browse) · [Extract](#extract) · [Create and edit](#create-and-edit) · [Split archives](#split-archives) ·
[Check and verify](#check-and-verify) · [Passwords](#passwords) · [Finder](#finder) · [While it works](#while-it-works) ·
[Updates](#updates) · [Settings and help](#settings-and-help) · [Keyboard shortcuts](#keyboard-shortcuts)

The list of formats ArchiveX reads and writes is in the [README](README.md#formats).

---

## Open and browse

- **Open anything ArchiveX understands.** Drop an archive on the window or the Dock icon, use *Open With → ArchiveX* in Finder, or press <kbd>⌘</kbd><kbd>O</kbd>.
- **Recent archives.** The welcome screen shows your last three archives as badges. Click one to open it; **Clear** empties the list.
- **Windows and tabs.** Each window or tab holds its own archive, so you can compare two side by side.
- **Folders inside the archive.** Double-click or press <kbd>Return</kbd> to go in, <kbd>⌘</kbd><kbd>↑</kbd> to go back up. The path bar shows where you are.
- **Search.** <kbd>⌘</kbd><kbd>F</kbd> searches names and paths. Wildcards work (`*.jpg`, `report-??.pdf`), and `.pdf` finds every PDF. <kbd>Esc</kbd> clears it.
- **Sort.** Click a column header to sort; the arrow shows the direction. Folders stay on top.
- **Type to jump.** Type the first letters of a name to select it.
- **Inspector panel (<kbd>⌘</kbd><kbd>I</kbd>).** Click a file to see a **preview** (images, text files and the first page of a PDF) and its details: size, packed size, ratio, date, CRC32. With nothing selected it shows the archive itself: format, size, contents, compression ratio, encryption and any comment. Previews never unpack very large files or locked ones.
- **Quick Look (<kbd>Space</kbd>).** Full-size preview of the selected file, without extracting everything.
- **View.** Opens the selected file in its own app (<kbd>⇧</kbd><kbd>⌘</kbd><kbd>V</kbd>).
- **Copy.** <kbd>⌘</kbd><kbd>C</kbd> copies the selected files so you can paste them into Finder.

## Extract

- **Extract To… (<kbd>⌘</kbd><kbd>E</kbd>).** Choose a folder and options. The suggested folder is named after the archive.
- **Extract Here (<kbd>⇧</kbd><kbd>⌘</kbd><kbd>E</kbd>).** Puts the files next to the archive.
- **Extract to Subfolder (<kbd>⌥</kbd><kbd>⌘</kbd><kbd>E</kbd>).** Makes a folder named after the archive. It is smart: if everything inside the archive is already in one folder, ArchiveX does not wrap it in a second one, so you never get *Photos/Photos/…*.
- **Only what you select.** Select files or folders first to extract just those.
- **If a file already exists:** overwrite, skip, or rename the new one.
- **Keep folder structure** or flatten everything into one folder.
- **Show in Finder** when it is done (you can turn this off).
- **Drag files out** of the window straight into Finder, Mail or any app. The file is only unpacked when it is dropped.
- **Safe by design.** Entries that try to escape the folder you chose (`../`, absolute paths, tricky links) are skipped and reported.
- **Fast on big ZIPs.** ZIP files are unpacked on all CPU cores at once.

## Create and edit

- **New Archive… (<kbd>⌘</kbd><kbd>N</kbd>).** Or drop files and folders on the window. Choose 7z, ZIP, RAR, TAR, TAR.GZ, TAR.BZ2 or TAR.XZ.
- **Compression level** from *Store* (no compression) to *Best*; **solid** archives for 7z.
- **Add and delete in place.** Add files to an open ZIP, 7z, RAR or TAR archive (<kbd>⇧</kbd><kbd>⌘</kbd><kbd>A</kbd>), or delete selected files from it (<kbd>⌘</kbd><kbd>⌫</kbd>).
- **ZIP comments.** Write a comment when you create a ZIP; it is kept when you edit the archive and shown in the inspector.
- **Test when done**, and **delete the originals afterwards**. The originals are only deleted after the new archive tests clean.
- **RAR note.** RAR archives made by ArchiveX store files without compressing them. Use 7z when size matters.

## Split archives

- **Create split archives** (`.001`, `.002`, …) for ZIP, 7z and TAR in 10 MB, 100 MB, 700 MB (CD), 4 GB (FAT32) or a custom size. The sheet tells you how many parts to expect.
- **Open split sets** by choosing any part. ArchiveX finds the rest and reads them as one archive. Info-ZIP sets (`.z01`) and multi-volume RAR sets open too.
- **Join split archive… (File menu).** Glues the parts back into one file next to them, never overwriting an existing file. It refuses a set with a missing part, because the result would be damaged.
- RAR is not offered for splitting: a plain byte split would not be a real RAR volume set.

## Check and verify

- **Test Archive (<kbd>⌘</kbd><kbd>T</kbd>).** Reads every file and checks it against its stored checksum.
- **Checksums (<kbd>⇧</kbd><kbd>⌘</kbd><kbd>K</kbd>).** CRC-32, MD5, SHA-1 and SHA-256 of the selected files, or of the archive itself, calculated in one pass. Paste an expected value to see whether it matches.
- **Damage is never ignored.** Files are checksummed while they are read, and a problem is reported in plain words ("This archive ends too early, so it is probably an incomplete download").

## Passwords

- **Encrypted archives ask for the password when needed**, and ask again if it was wrong.
- **Create protected archives.** AES-256 for ZIP, 7z and RAR. 7z can also hide the file names.
- **Compatibility switch for ZIP.** Optional ZipCrypto so macOS Archive Utility can open it (weaker; ArchiveX warns you).
- **No command line is ever involved**, so passwords never appear in a process list.

## Finder

- **Right-click → Services / Quick Actions:** *Compress with ArchiveX*, *Extract with ArchiveX*, *Test with ArchiveX*. Install the Quick Actions from the **ArchiveX** menu (**Install Finder Quick Actions…**).
- **Open With → ArchiveX** for any supported archive.
- **Drag in and out.** Drop files on the window to compress them, drag files out to extract them.

## While it works

- **Progress that tells you something.** A percentage, the time left and the time elapsed, with a **Cancel** button (<kbd>Esc</kbd>).
- **Dock percentage.** The Dock icon shows progress while a job runs.
- **Notification when it finishes.** If a long job ends while you are in another app, you get a notification and the Dock icon bounces once. Turn it off in Settings.
- **Plain-language errors.** Messages say what went wrong and what to try next: an incomplete download, a wrong password, a full disk, a folder ArchiveX is not allowed to write to.

## Updates

- **Check for Updates…** (ArchiveX menu) and a quiet check every time the app starts. Turn the automatic check off any time.
- **See what changed** in the update window, then **Install & Restart**, **Skip This Version** or **Later**.
- **Updates are verified.** The download must come from GitHub, match its checksum, be signed with the ArchiveX update key, have the right bundle identifier and be newer than your copy. A fake update cannot be installed even if someone controlled the release page.
- ArchiveX replaces itself and restarts; nothing is left behind. If it cannot replace itself, it shows the new app in Finder.

## Settings and help

- **Settings (<kbd>⌘</kbd><kbd>,</kbd>).** Default format and compression level, what to do when a file exists, show in Finder after extracting, notifications, and update checks.
- **Help menu.** *Features & Shortcuts* (this page), *Report a Bug…* and *Request a Feature…* (open a new GitHub issue with your version, macOS and Mac type already filled in; nothing about your files is sent), *ArchiveX on GitHub* and *Known Issues*.
- **Install in one line** without the macOS download warning: see the [README](README.md#install).

---

## Keyboard shortcuts

| Do this | Press |
|---|---|
| Open an archive | <kbd>⌘</kbd><kbd>O</kbd> |
| New archive | <kbd>⌘</kbd><kbd>N</kbd> |
| Close the archive | <kbd>⌘</kbd><kbd>W</kbd> |
| Search | <kbd>⌘</kbd><kbd>F</kbd> (clear with <kbd>Esc</kbd>) |
| Select all | <kbd>⌘</kbd><kbd>A</kbd> |
| Copy the selected files | <kbd>⌘</kbd><kbd>C</kbd> |
| Open a folder or file | <kbd>Return</kbd> or <kbd>⌘</kbd><kbd>↓</kbd> |
| Go up one folder | <kbd>⌘</kbd><kbd>↑</kbd> |
| Jump to a name | Type its first letters |
| Quick Look | <kbd>Space</kbd> |
| Inspector panel on / off | <kbd>⌘</kbd><kbd>I</kbd> |
| Extract To… | <kbd>⌘</kbd><kbd>E</kbd> |
| Extract Here | <kbd>⇧</kbd><kbd>⌘</kbd><kbd>E</kbd> |
| Extract to Subfolder | <kbd>⌥</kbd><kbd>⌘</kbd><kbd>E</kbd> |
| Add files to the archive | <kbd>⇧</kbd><kbd>⌘</kbd><kbd>A</kbd> |
| Test the archive | <kbd>⌘</kbd><kbd>T</kbd> |
| Checksums | <kbd>⇧</kbd><kbd>⌘</kbd><kbd>K</kbd> |
| View the selected file | <kbd>⇧</kbd><kbd>⌘</kbd><kbd>V</kbd> |
| Delete from the archive | <kbd>⌘</kbd><kbd>⌫</kbd> (or <kbd>⌫</kbd>) |
| Cancel a running job | <kbd>Esc</kbd> |
| Settings | <kbd>⌘</kbd><kbd>,</kbd> |
