# SlackDump

A tool to **dump all the conversations** from all the channels from all the workspaces a slack cookie has access to. Then, you can **search sensitive information in this dump**.

Just get the value of the **cookie `d`** from your browser and pass it in the `--cookie` param.

```bash
pip3 install -r requirements.txt
python3 SlackDump.py --output-dir /tmp/slackdump --cookie xoxd-6DTKNJ/4[...]
```

You can use the tools **[gitleaks](https://github.com/zricethezav/gitleaks)** and **[trufflehog](https://github.com/trufflesecurity/trufflehog)** to search for secrets in the dump.

```bash
# Find secrets with gitleaks
gitleaks detect -s /tmp/slackdump --no-git --report-format json --report-path /tmp/gitleaks_found.json
## Remove some false possitives
cat /tmp/gitleaks_found.json | jq 'unique_by(.Match)' | jq '.[] | select(.Match | contains("client_msg_id") or contains("token=") or contains("author_name") | not)'

# Find secrets with trufflehog
trufflehog filesystem --directory /tmp/slackdump --json [--only-verified]
```

**TODO**: Add option to dump all files from all channels.

Thanks to **[SlackPirate](https://github.com/emtunc/SlackPirate)** for the initial idea and research on Slack cookies.
