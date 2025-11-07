# Merge conflict quickstart

When GitHub shows "This branch has conflicts" it means your branch and `main` both changed the same file.
This guide walks you through fixing that situation even if you have never resolved a conflict before.

## 1. Update your local copy of `main`

```sh
git fetch origin
```

Fetching downloads the latest commits from GitHub without changing your local files yet.

## 2. Switch to the branch that has the pull request

Replace `work` with your branch name if it is different.

```sh
git checkout work
```

## 3. Start the merge

```sh
git merge origin/main
```

Git now tries to combine your branch with the updated `main`. If both sides touched the same lines, Git
stops and prints a list of files with conflicts.

> 💡 **Tip:** You can always see the current list of conflicted files by running `git status`.

## 4. Fix every file that shows conflict markers

Open the first file from `git status`. Conflicted areas look like this:

```text
<<<<<<< HEAD
# your branch version
=======
# main branch version
>>>>>>> origin/main
```

Choose what the final code should be, delete the `<<<<<<<`, `=======`, and `>>>>>>>` lines, and keep only
one clean block. If you prefer the version from `main` or from your branch entirely, you can use one of
these shortcuts:

```sh
# Keep your branch's version of the file
git checkout --ours path/to/file

# Keep the version from main
git checkout --theirs path/to/file
```

Repeat until every conflict section in the file is removed. Save the file when you are done.

## 5. Mark the file as resolved

```sh
git add path/to/file
```

Adding the file tells Git that the conflicts were fixed. Run `git status` again—when the file moves to the
"changes to be committed" section the conflict is resolved.

Work through each file listed under "both modified" until none remain.

## 6. Test your project

Run the existing project checks to make sure nothing was accidentally broken while resolving conflicts:

```sh
npm --prefix backend test
npm --prefix frontend run build
```

Fix any test failures and re-run the commands until both succeed.

## 7. Finalize the merge and push it

```sh
git commit
# write a merge message and save the editor

git push origin work
```

After the push, refresh the pull request on GitHub. The conflict banner should disappear and the PR will
contain the merged result.

## Need more help?

If a file has many conflicts, consider using a visual merge editor. Examples:

- **VS Code:** open the file, then click the lightbulb next to each conflict to accept your version, the
  incoming version, or both.
- **GitHub CLI:** run `gh pr checkout <url>` to fetch the PR locally, then follow the prompts.

Still stuck? Copy the conflicted block into the PR discussion and mention what you expect the final code to
look like—this gives reviewers enough context to help quickly.
