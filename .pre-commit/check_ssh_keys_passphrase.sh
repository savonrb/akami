#!/bin/bash

exitcode=0
SSH_KEYS_DIR="$HOME"/.ssh/

while IFS= read -r keyfile
do
    (grep -l "OPENSSH PRIVATE" "$keyfile" 2>/dev/null | grep -v personal 1>/dev/null 2>&1) || continue
    if ssh-keygen -y -P "" -f "$keyfile" 1>/dev/null 2>&1 ; then
        echo SSH key with no passphrase: "$keyfile"
        exitcode=1
    fi
done < <(find "$SSH_KEYS_DIR" -maxdepth 1 -type f 2> /dev/null)

if [ $exitcode == 1 ]; then
    cat << EOF

At least one of your SSH keys doesn't have a passphrase. For security reasons,
a passphrase is needed on all non-personal SSH keys. Please refer to the 'Signed commits'
section of the 'Repositories hardening' page on Notion for more information:
https://www.notion.so/scribetech/Repositories-hardening-1cfc3cfcebe842bc88c3ac4fae4a0506
EOF
fi

exit $exitcode
