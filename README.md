Script in Python to modify artifacts from a [Fossil](https://fossil-scm.org/home/doc/trunk/www/index.wiki) repository. Currently it only allows to rename articles of the wiki.

Dependencies:

* [pysha3](https://github.com/tiran/pysha3) (only in Python 3.5 and earlier).
* Fossil, either installed on the system or the path to the executable as a script parameter.

# Usage
`fossil_editor.py oldname newname repo.fossil`

Article with spaces in the name:

`fossil_editor.py "name with spaces" "new name" repo.fossil`

Using with the Fossil executable in the same directory where the repository is located:

`fossil_editor.py oldname newname repo.fossil ./fossil`

# ⚠ WARNING ⚠
The script is still considered very experimental. Although in the tests that I have done it works correctly, I do not rule out the possibility that it can generate data corruption in your repository.

Because of the above, before using it is recommended to make a backup of the repository or have a test repository to run the script before applying changes to the real repository.

In short, NO WARRANTY for any damages and/or loss of data.
