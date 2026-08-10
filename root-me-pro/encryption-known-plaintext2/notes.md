# notes
- len 2222, repeating XOR
- key length 5 (Hamming dips at 5,10,15,20,25,30,35)
- crib %PDF-1. -> key = 1c 27 98 51 2f
- decoded.pdf = PDF 1.3 ReportLab, has /Encrypt (empty pw)
- mutool draw -F txt decoded.pdf -> flag
- FLAG: RM{4a8a5bd8453fbdfbe51aa480676df4bb}
