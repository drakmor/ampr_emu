# Contents

## Two ways to work

Auto Guide walks you through the process with explanatory windows. Manual controls let you choose each operation yourself. Both use the same project and recovery records. Python is included; no Terminal setup is needed.

## Page 2: Start Auto Guide

Select the game and working folder. Choose whether to use an existing TOML.

## Page 3: Record on the PS5

Prepare the recording emulator, play, and save the recording automatically.

## Page 4: Profile and acceptance

Create the TOML and output location, load the profile and confirm loose files.

## Page 5: Build, verify and finish

Follow progress, choose verification and create the complete PAK game.

## Page 6: Manual controls

Select all five paths and run operations independently.

## Page 7: Update EMU files

Choose recording, PAK or manual-update versions.

## Page 8: Close, Continue, Step Back and Stop

Pause the guide, resume a project or cancel an operation.

## Page 9: Recovery and cleanup

Restore the original game and decide when to remove your working folder.

# Start Auto Guide

## Open the app

Open AMPR Pack Tools.app and click Auto Guide. All guided steps use the same window style. OK continues, Close pauses. Step Back returns to the previous step and undoes the changes recorded for that step.

## Step 1: Select the game

Choose your complete game folder. You can use a game on an internal or external drive. If you already selected a Game folder in the main window, the guide uses it. Start from a complete original game, not a reduced PAK game.

## Step 2: Choose the working folder

Select a folder outside the game and outside the locations your PS5 loader scans for games. On an external drive, the chooser starts at the top level of that drive. Navigate first, then use New Folder. This folder holds the project, recordings, outputs and original backup.

## Step 3: Answer the TOML question

The app asks whether you already have a TOML profile before it creates an index. If this is your first time hearing about a TOML file, click No. If you have a suitable template for this game, click Yes and select it.

## How the project is saved

The app creates <game-folder-name>.json in your working folder. Completed steps and the next step are saved automatically. Keep the hidden .ampr-projects folder too. The project is the record of your work, not a substitute for your game backup.

## About step numbers

Numbers in the app follow the route you chose. The existing-TOML route skips recording and profile generation, so its later step numbers are lower. This guide names the actions to help you follow either route.

# Record on the PS5

## Prepare game files

Both routes check fakelib, libSceAmpr.sprx and ampr_emu.index. Missing folders are created. The existing SPRX and index are backed up before replacement. The index is rebuilt from the complete game files, not from the SPRX. Step Back and Recovery record these changes.

## Which emulator is installed?

Without a TOML, the app installs the recording version (test-debug-pack). With an existing TOML, it installs the PAK-capable version without recording (test-pack) immediately, then skips gameplay recording. Both are installed as fakelib/libSceAmpr.sprx. This does not configure your PS5 loader.

## Record on your PS5

After preparation, follow the Record on your PS5 window. Safely eject an external game drive and connect it to the PS5. Play for about 5-10 minutes for a first recording. Try different areas and actions. A short recording does not cover the whole game.

## IMPORTANT: when to click OK

Close the game normally, reconnect the game drive to the Mac at the same location, and only then click OK. The next step copies the recording. Closing this window pauses the guide; it does not force you to start over.

## Save recording happens automatically

The app creates Recordings in your working folder, then a dated run folder for this session. It copies ampr_commands.bin and its matching ampr_emu.index, plus ampr_emu.log if present. No folder selection is needed. The files in the game folder remain in place.

## If the game is copied between devices

Bring the session’s command file, matching index and optional log back into the project’s game folder before continuing. Do not mix recordings and indexes from different games or updates. For the existing-TOML route, this recording stage is skipped.

# Profile and acceptance

## Create the profile and output location

The guide explains that it will create a TOML profile named after your game and a Pack Output folder in your working folder. Click OK. Existing files are not overwritten; a numbered name is used when needed. A previously selected existing TOML is retained.

## Generate profile from recordings

For the recording route, the next window explains profile generation. Click OK to analyse the saved recordings, also called traces. The app fills in the TOML and creates a report and metrics. A separate success message confirms completion.

## Load and check the profile

After OK, the guide loads and checks the profile. You do not need to return to the main window and click Load from profile. The check covers configuration and the available memory estimate. It cannot certify every scene, language or DLC.

## Confirm loose files

The guide explains that files not packed will remain as loose files in the finished game. Select I understand. Keep unselected files loose, then click Accept and start. This confirms the choice and starts the guided build.

## If you decline

Nothing starts. The project stays at the acceptance step. Click Continue when ready; the confirmation appears again. Close also pauses at this point.

## Why loose files matter

A recording sees only the reads made during that session. Files absent from it are not automatically deleted. At finalisation, the app copies every actual file that was not packed, apart from recording files and setup-generated backups.

# Build, verify and finish

## Follow the build

The guide shows a progress window with percentage and estimated remaining time. Close hides the progress window while the operation continues. Use Stop to request cancellation. The main log remains available for details.

## Choose verification

After the build, choose Verify or Skip verification. Verify reads the PAK data and compares it with the original files, so it takes additional time. Skip omits this byte comparison. Basic structure and memory checks still run, and the result is explicitly marked UNVERIFIED.

## Finish PAK game

The app creates a folder named after your game inside PAK Output. It moves the existing PAKs there and copies only the remaining loose game files. It then moves the original into Original game in your working folder and puts the finished PAK game at the original location.

## Runtime and indexes

The app installs fakelib/libSceAmpr.sprx with PAK support and recording disabled. NoPack is not the right variant for a PAK game. ampr_commands.bin and ampr_emu.log are excluded. ampr_emu.index stays unchanged; do not rebuild it against the reduced game. Keep the matching ampr_assets.index sidecars.

## Wait for Success

Packing at 100% does not mean finalisation is complete. Wait for the final Success window before disconnecting a drive. The app does not automatically eject drives. Then test the finished game on your PS5.

## Keep enough space

Moves within one volume need no second PAK copy. Different volumes require a transfer and take longer. Keep enough space for the remaining loose files and any transfer. Do not delete original assets.

# Manual controls

## Choose the paths yourself

Browse is available for Game folder, ampr_emu.index, Trace directory, TOML profile and PAK output directory. You can also enter paths. A manually selected index must match the game and its file IDs. Use New Project to change games rather than repointing an existing recovery record.

## No automatic guide windows

The manual buttons run their own operations. They do not launch the guide. Results appear in the log, with error messages and confirmation windows where needed. Auto Guide and Continue are separate choices.

## Create a profile manually

Save or select a recording archive, choose the TOML filename and output folder, then click Generate profile from traces. Click Load from profile to view the include patterns. Add files or remove patterns if desired, then Save selection and Check profile.

## Acceptance does not start a manual build

If the loose-files checkbox is empty, Create PAKs and verify asks you to accept. Accept sets the checkbox but does not start the build. Click Create PAKs and verify again when ready. Decline leaves the build stopped.

## Verify existing PAKs

Select the original game, matching index, TOML and existing PAK output folder. Verify existing PAKs compares the set with the originals. Finish PAK game is a separate action in manual mode.

## Continue after a stop

The project remembers the pending operation. After cancellation cleanup finishes, Continue can restart that operation. A stopped PAK build restarts from the beginning; it does not resume part-way through a compressed file.

# Update EMU files

## Add new versions

Emulator files chooses which libSceAmpr.sprx version the app uses. The normal Auto Guide already selects included versions. To use another version, browse to a downloaded SPRX or place it in the package’s emus folder. Selecting it here does not modify the game yet.

## Choose the role

Recording records file accesses while you play. PAK game reads the PAK files in the finished game without recording: this is what PAK runtime means. Manual update chooses a version for a separate update. The selected file and its fingerprint are saved in the project.

## Names are hints

No-Pack and no debug are different properties. A bare version number does not prove either capability. Known bundled files are identified by their contents. Unknown versions ask you to confirm PAK support and recording behaviour from the release information; PAK versions also ask for their documented memory-pool size.

## Update emulator only

Select a game, click Update emulator only and choose the SPRX. A missing fakelib folder is created, and an existing libSceAmpr.sprx is backed up. This action does not rebuild the index.

## Create / rebuild index

This creates ampr_emu.index from the game files and backs up any current index. It does not change libSceAmpr.sprx. Do not use it on a reduced PAK game, because rebuilding would change the file-ID mapping.

## Set up both

This installs the selected SPRX in fakelib and creates the index. Use it for a complete original game. Missing files are created; existing ones are backed up. A future emulator version may change formats or requirements, so a recognised filename alone is not a compatibility guarantee.

# Close, Continue, Step Back and Stop

## Close an idle step

Close pauses the guide. The next step remains saved in the JSON project. Open Project restores it after restarting the app; Continue returns to that point.

## Step Back

Step Back restores the previous step’s recorded settings and file changes. It removes only generated files registered for that step, and restores files that existed before the step. It does not remove unrelated files placed in a shared folder.

## During an operation

The guide has its own progress window; manual mode uses the large log panel. Both have Stop. Hiding a progress window is not cancellation. Keep the drives connected until the operation or its cleanup has finished.

## Two stages before stopping

First confirm the Stop warning. A ten-second countdown then appears with Cancel. Cancel dismisses the stop request and lets the work continue. When the countdown ends, the operation is stopped and its recorded step changes are undone where a checkpoint is available.

## PAK cancellation

The build uses a private staging folder. Cancellation removes that build’s staging and published output files, not your original game. Continue can start the build again. An interrupted finalisation may take time to undo because game folders must be restored.

## Older projects and interruptions

Steps created by older app versions may not have individual checkpoints. The app cannot invent that history. It may require full Recovery before starting a new project. Reconnect missing drives first; do not run two app instances on the same project.

# Recovery and cleanup

## Recover original game is separate

Recovery is not an automatic step at the end of the guide. Click Recover original game only when you want to undo the project. The warning explains that it restores the state captured when the project was created.

## Confirmation and countdown

Choose Yes, then wait through the ten-second countdown. Cancel is available until it expires. Recovery restores the original first. Only after that succeeds does it permanently remove project-generated PAKs, recordings and temporary files. It does not archive the PAK game.

## What is removed and what stays

Generated files and saved progress are removed. Imported and pre-existing files are kept. Unrecognised files are left alone. Within one volume the original is moved back; different volumes require a transfer. A small project status file remains, and New Project can reuse the same working folder.

## To keep Recovery available

Until you choose Recovery, keep the project, hidden .ampr-projects folder, original backup and related files at their saved locations. Recovery needs these backups. Once recovery and cleanup succeed, the project is reset. Step Back remains a separate action that preserves the work needed to continue.

## After a successful PS5 test

The final window displays your actual working-folder path. If you no longer need recovery or further project work, you may delete the dedicated working folder yourself. First make sure it contains no unrelated data and is not a parent folder of the finished game. Deleting the original backup removes this project’s recovery option.

## About this Mac release

Apple Silicon only. Python and LZ4 are bundled. The app is locally signed and not Apple-notarised. This revision was built without additional app, PAK or PS5 test runs at the user’s request. Test with your own retained original. UPSTREAM documents are technical references, not this new guide.