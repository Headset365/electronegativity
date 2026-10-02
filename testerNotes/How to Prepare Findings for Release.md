<!-- Electronegativity tester notes: not part of the client report -->

# How to Prepare Findings for Release

This guide explains, step by step, how to get each finding ready to give to the client. Every finding has a file of tester notes in the `testerNotes` folder. At the end of each tester notes file there is a list called **Before release**. Each item in that list links to a part of this guide. Do the items in order, and tick each one when it is done: change `- [ ]` to `- [x]`.

Some things to know first:

- The client findings are the files in the `reports` folder. These are the only files that go to the client.
- The files in the `testerNotes` folder, including this guide, are for you. Never send them to the client.
- To edit a finding, open its `.md` file in a text editor. Visual Studio Code is a good choice: it can show the finding as it will look (press **Ctrl+Shift+V**). Notepad also works.
- Each finding starts with a block between two lines of `---`. This block holds the Title, the Consequence, the Likelihood and the Notes. Change only the words after the colons, and keep the spaces at the start of each line exactly as they are.
- Your changes are not lost if the findings are written again later. If you run `electronegativity --rerender`, it writes new findings into a separate folder and lists every change you made, so you can copy them across.

## Read the finding

1. Open the finding in your text editor.
2. Read it from the first line to the last, slowly.
3. Check that the application’s name is right everywhere it appears.
4. Check that there are no folder paths from your own computer, user names, or internal server names that the client should not see.
5. Look at each bullet under **Issue Description** and **Implication**. Each one describes one way the issue applies. If a bullet does not apply to this application, delete that bullet (the whole line).
6. If you deleted a bullet, delete the matching bullet under **Recommendations** too, and remove its name from the lines under **Affected**.
7. Read it once more to make sure it still makes sense.

## Mask secrets

A secret is anything that lets someone log in or use a service: an API key, a token, a password, a session cookie or a private key. The finding may show secrets in its code, in a URL, in a sentence that says what testing saw, or in a screenshot. The client needs to know which secret it is, but the report must not give it away.

1. Open the finding in your text editor.
2. Press **Ctrl+F** and search for each of these words, one at a time: `key`, `token`, `secret`, `password`, `passwd`, `pwd`, `auth`, `bearer`, `cookie`, `session`, `sk_`, `AKIA`, `AIza`, `ghp_`, `xox`, `eyJ`. Also look for any long string of random-looking letters and numbers.
3. Look in every part of the finding: the code under **Reproduction and Evidence**, the lines under **Affected** (URLs can hold tokens after a `?`), and the sentences that start with "During testing".
4. For each secret you find, keep the first 4 and the last 4 characters and replace everything in between with the letter `X`. For example, `sk_live_51HabcdefGHIJKL3f9a` becomes `sk_lXXXXXXXXXXXXXXXXXXX3f9a`. Use `X`, not `*`: outside code, `*` changes how the text looks.
5. If the secret is very short (fewer than 12 characters), replace all of it with `XXXXXXXX`.
6. Make sure you masked the same secret everywhere it appears in the finding: search for its first 4 characters to find any copies.
7. If the finding has screenshots, follow "Check the screenshots" below as well.
8. Save the file.

## Check the screenshots

1. In the finding, find each picture. In the file it looks like `![name.png](../path/name.png)`. The part in brackets is where the picture file is.
2. Open that picture file (double-click it in File Explorer).
3. Look carefully for: people’s names, email addresses, account numbers, document contents, tokens or cookies, and internal server names.
4. If you find something private, open the picture in **Paint** (right-click the file, then **Open with**, then **Paint**).
5. Click **Select**, drag a box over the private part, and press **Delete**. Or pick black as the colour and draw a filled rectangle over it.
6. Click **File**, then **Save** (keep the same name, so the finding still shows it).
7. Open the finding’s preview (**Ctrl+Shift+V** in Visual Studio Code) to check that the picture still shows.

## Check whether a credential works

The tool found something that looks like a credential in the application’s files. The finding is more serious if it still works.

1. Never try the credential yourself against a live service unless the client has said yes in writing.
2. Look at the start of the value. Some tell you what kind it is: `sk_live_` is a live Stripe key and `sk_test_` a test one; `AKIA` is an Amazon key; `AIza` is a Google API key (these are often meant to be public, but should be restricted); `ghp_` is a GitHub token.
3. Send the client contact the masked value (see "Mask secrets") and the file it was found in, and ask: Is this a real credential? Does it still work? What can it do?
4. When they answer, write one sentence about it in the finding, under **Issue Description**, after the first paragraph. For example: "The client confirmed that the key was active at the time of testing."
5. If the client says it is not a credential, or is a public key meant to be shared, lower the rating (see "Check the rating") or delete the finding if nothing else is in it.

## Review an instance by hand

Some instances were flagged by the tool as needing a person to check them, or were found with low (tentative) confidence. That means the code looks like the problem, but the tool could not be sure.

1. Open the tester notes for this finding and find the list called **Recorded evidence (all instances)**. Each instance there shows a file and a line number.
2. Open the application’s code (see "Open the application code" below) and open that file.
3. Go to the line: in Visual Studio Code, press **Ctrl+G**, type the line number and press **Enter**.
4. Read the line and the lines around it. Ask yourself: can someone who is not trusted (another user, a web page, a document, a link) control the value used here?
5. If yes, or if you are not sure, leave the instance in the finding.
6. If no (for example, the value is fixed in the code and never changes), it is a false positive. Delete its line under **Affected**, and its bullet under **Reproduction and Evidence** if it has one.
7. If every instance in a finding is a false positive, delete the whole finding file, and write in its tester notes why.

## Decide about instances not validated

For this finding, the client report only shows instances that were proved while the application was running. The others are listed under **Affected**, but not shown as evidence.

1. Open the tester notes for this finding and look at **Recorded evidence (all instances)**. The ones with "Validation: not run" or "inconclusive" are the ones left out.
2. Choose one of these:
   - Leave them out. The finding still lists their locations under **Affected**. This is fine when at least one instance is proved.
   - Prove them. Run the tool again with `--app`, and during the session follow the `[validate]` lines it prints in the terminal. Each proved instance is then added to the evidence automatically.
   - Delete them. If you check them by hand (see "Review an instance by hand") and they cannot be reached, delete their lines under **Affected**.
3. If no instance at all was proved, think about whether the rating is still right (see "Check the rating").

## Confirm what the user has to do

Some issues only happen if a user does something: clicks a link, opens a document, or installs an update. The Likelihood depends on how normal that is.

1. Read the **Implication** section and the note that starts with *Note:* to see what the user has to do.
2. Ask yourself, or the client: do users of this application normally do that? For example, do they open documents sent by other people?
3. If it is something users do every day, the Likelihood can stay or go up.
4. If users would almost never do it, lower the Likelihood (see "Check the rating").

## Confirm who owns a host

The finding names servers (hosts) that the application sent data to. Whether that is a problem depends on who owns them.

1. Make a list of the host names in the finding (under **Affected** and in the "During testing" sentences).
2. Send the list to the client contact and ask which ones belong to them or to a supplier they have a contract with.
3. If you cannot ask, open PowerShell and run `Resolve-DnsName host.example.com` for each one, and search the name on the web to see what company it belongs to.
4. If a host belongs to the client, delete the bullet that says data is sent to third parties for that host.
5. If every host belongs to the client, and nothing else is left in the finding, delete the finding.

## Check the accepted risks

An accepted risk is an instance the client has already said they accept. It is listed in the **Notes** at the top of the finding.

1. Read each "Accepted risk" line in the Notes at the top of the finding.
2. Check the date after "Expires", if there is one. If that date has passed, the risk is no longer accepted: ask the client whether to keep it.
3. Check that the owner named is still the right person.
4. If the client no longer accepts the risk, delete its line from the Notes, so the instance is treated like any other.

## Check the components workbook

The Outdated Software Components finding refers to the `components.xlsx` file in the `reports` folder.

1. Open `components.xlsx` in Excel.
2. Stay on the first sheet, "Components needing action".
3. Look at the column "Links to validate manually". If it is empty in every row, you are done.
4. For each row where it is not empty, click each link named there.
5. If the page opens and shows that component, the link is fine.
6. If it shows "not found", search the web for the component’s name and version, find the right page (for example on npmjs.com or the vendor’s own site), copy its address, and paste it into the cell over the broken link.
7. When every link in a row works, delete the text in that row’s "Links to validate manually" cell.
8. Save the file.

## Check the rating

Each finding has a **Consequence** (how bad it would be) and a **Likelihood** (how likely it is to happen), at the top of the file.

- Consequence, from lowest to highest: `Very Low`, `Low`, `Medium`, `High`, `Critical`.
- Likelihood, from lowest to highest: `Rare`, `Unlikely`, `Possible`, `Likely`, `Very Likely`.
- `N/A` for both means the finding is a hardening observation or is rated Informational.

1. Open the tester notes for the finding and read **Rating basis**: it says which instance set the rating and why.
2. Think about what you learnt in the checks above. Was something proved that makes it worse? Did the client tell you something that makes it less likely?
3. To change the rating, edit the words after `Consequence:` or `Likelihood:` at the top of the finding. Use exactly one of the words in the lists above, spelt the same way.
4. If you changed it, add one sentence to the tester notes saying why, so the next person knows.

## Open the application code

For an installed application, the code is packed into one file called `app.asar`.

1. Open File Explorer and go to the folder where the application is installed (for example `C:\Program Files\MyApp`).
2. Open the `resources` folder. If you see a folder called `app`, the code is already unpacked in it: open that folder, and you are done.
3. If you see a file called `app.asar` instead, click the address bar at the top of File Explorer, type `powershell` and press **Enter**. A PowerShell window opens in that folder.
4. Type this and press **Enter**: `npx @electron/asar extract app.asar "$env:USERPROFILE\Desktop\app-code"`
5. A folder called `app-code` appears on your desktop. The file paths in the findings are relative to this folder.
6. If the tool scanned the application’s source code instead, the paths are relative to the source code’s main folder.
