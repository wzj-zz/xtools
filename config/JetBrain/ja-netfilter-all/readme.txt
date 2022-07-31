License code: 
    1. add -javaagent:/path/to/ja-netfilter.jar=jetbrains to your vmoptions (manual or auto)
    2. log out of the jb account in the 'Licenses' window
    3. use key on page "index.html"
    4. plugin 'mymap' has been deprecated since version 2022.1
    5. don't care about the activation time, it is a fallback license and will not expire

Or

License server:
    1. add -javaagent:/path/to/ja-netfilter.jar=jetbrains to your vmoptions (manual or auto)
    2. log out of the jb account in the 'Licenses' window
    3. uninstall plugin: 'IDE Eval Reset'
    4. use license server url: https://jetbra.in

Enjoy it~

JBR17:
    add these 2 lines to your vmoptions file: (for manual, without any whitespace chars)
    --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED
    --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED

NEW: 
    Auto configure vmoptions (Copy from Neo):
    macOS or Linux: execute "scripts/install.sh"
    Windows: double click to execute "scripts\install-current-user.vbs" (For current user)
                                     "scripts\install-all-users.vbs" (For all users)
