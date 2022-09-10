Question:

Given a zip full of signed .exe files , can we prove that they are indeed the original Monero Binaries? Join me

TLDR

These are indeed signed Monero binaries - but with trailing zeros after signature is removed and an incorrect internal checksum value (which is just a string, not a real checksum), which once corrected, gives us a file identical to the original.

Remove signature

Signatures will be removed using osslsigncode with the command remove-signature

```
osslsigncode remove-signature monerod.exe monerod.exe.nosig
```

the resulting file monerod.exe.nosig has a different sha256sum hash and using vbindiff to investigate we can see the file differs in 2 places from the official monerod.exe 

2 images

The most straight forward thing we can do is simply remove the padded zeros at the end of the file, which leaves the other tiny difference behind.

Opening monero.exe.nosig.nozero in PE-Bear (a tool for reversing Packaged Executible files) we see that the reason the original monerod.exe and monerod.exe.nosig.nozero differ is because of an internal checksum value (highlighted red because it is incorrect) - our new file with no signature and trailing zeros removed is identical to the official monerod.exe , we just have to change the string value of this checksum to be correct (the same of the original). My operating system Ubuntu even places a padlock on the files icon to warn that the checksum is incorrect.

image 

more detailed information about this checksum value can be found here https://practicalsecurityanalytics.com/pe-checksum/


blockchain-export.exe

This file is special, it is the only one which is identical to the original file after its signature is removed. This is because the tool used to sign the executable does not need to add any zero's and it can append the signature at the end of the file on a new line.

Conclusion

I am satisfied beyond all resonable doubt that these files are original, un-altered signed Monero executables and i will sign the hash of the zip file myself and create a github workflows script to prove my findings.


integirty verified 

