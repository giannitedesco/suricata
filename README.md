# Suricata: DumpJSON

This is the `dump-json` branch, which is a work in progress to add a new
feature to Suricata that allows users to inspect and analyze the rules that are
being parsed and understood by Suricata.

I have developed it in order to verify another project, a Suricata rule
compiler, to ensure that the semantic analysis of the rules is correct and that
the rules are being parsed as expected.

Two new modes are added to Suricata in this branch:
- `--list-keywords=json`, which adds JSON to the list for formats in which
  keywords can be listed.
- `--dump-rules=output.json`, which dumps the rules in JSON format to the
  specified output file.

You can read the original README.md file for this project on GitHub:
[Suricata](http://github.com/OISF/suricata/).
