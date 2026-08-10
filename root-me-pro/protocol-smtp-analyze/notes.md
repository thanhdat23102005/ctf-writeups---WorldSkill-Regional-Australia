# Protocol - SMTP - Analyze (Root-Me Pro, Network, 200pts)

## Step 1
- 115 SMTP sessions in smtp-capture.pcap, all "Summer internship application" from 6 students to various companies.
- Extracted all emails: `tshark -r smtp-capture.pcap --export-objects "imf,extracted"`
- All attachments were `@CV-<Name>.pdf` EXCEPT one: frame set in "Summer internship application(36).eml"
  - From: thibault.delahaie@secure-mind-university.leet
  - To: workforce@pioneerstream.ddd
  - Attachment: `@CV-Thibault-DELAHAIE.exe` (disguised executable, not a PDF)
- Answer: thibault.delahaie
