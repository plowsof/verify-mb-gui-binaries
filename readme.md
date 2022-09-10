### Question:

Given a zip full of signed .exe files , can we prove that they are indeed the original Monero Binaries? Join me

### TLDR

These are indeed signed Monero binaries - but with trailing zeros after signature is removed and an incorrect internal checksum value (which is just a string, not a real checksum), which once corrected, gives us a file identical to the original.

### Remove signature

Signatures will be removed using osslsigncode with the command remove-signature

```
osslsigncode remove-signature monerod.exe monerod.exe.nosig
```

the resulting file `monerod.exe.nosig` has a different sha256sum hash and using vbindiff to investigate we can see the file differs in 2 places from the official `monerod.exe`.    

Here:    

![Screenshot from 2022-09-10 13-07-33](https://user-images.githubusercontent.com/77655812/189482664-2c4f0609-c297-4cd5-ae5d-b4823e871604.png)
And the end of the file here:
![Screenshot from 2022-09-10 13-07-47](https://user-images.githubusercontent.com/77655812/189482687-64d49c73-6928-487c-9f8a-b32d18142da5.png)

The most straight forward thing we can do is simply remove the padded zeros at the end of the file, which leaves the other tiny difference (06 instead of 01) behind.

Opening monero.exe.nosig.nozero in PE-Bear (a tool for reversing Packaged Executible files) we see that the reason the original monerod.exe and monerod.exe.nosig.nozero differ is because of an internal checksum value (highlighted red because it is incorrect) - our new file with no signature and trailing zeros removed is identical to the official monerod.exe , we just have to change the string value of this checksum to be correct (the same of the original).    
![Screenshot from 2022-09-09 22-23-57](https://user-images.githubusercontent.com/77655812/189482748-bc4f97a4-9c5e-4295-850e-6536d07bc123.png)

My operating system Ubuntu even places a padlock on the files icon to warn that the checksum is incorrect.
![Screenshot from 2022-09-10 09-30-22](https://user-images.githubusercontent.com/77655812/189482830-2397332d-95a3-4792-b8d9-bf1d57eb7d8c.png)

For `monerod.exe.nosig.nozero` - all we have to do is change the "06" to an "01" and now the sha256sum matches the original file thus verifying the integrity of the signed file.

More detailed information about this checksum value can be found here https://practicalsecurityanalytics.com/pe-checksum/

### blockchain-export.exe

This file is special, it is the only one which is identical to the original file after its signature is removed. This is because the tool used to sign the executable does not need to add any zero's and it can append the signature at the end of the file on a new line.

Original blockchain-export.exe does not need any padding at the end and thus the signature is on 'a new line':
![Screenshot from 2022-09-10 13-20-12](https://user-images.githubusercontent.com/77655812/189483117-3cdf83fc-bde4-4cf2-ac9d-1d661061dcc8.png)

### Conclusion

I am satisfied beyond all resonable doubt that these files are original, un-altered, signed Monero executables and have no problem in signing the hash value of the zip file with my pgp key. I will also create a workflows script to prove my findings.

In the workflow script , we can see the 06 -> 01 difference [here](https://github.com/plowsof/verify-mb-gui-binaries/runs/8285192387?check_suite_focus=true#step:7:55)

![Screenshot from 2022-09-10 15-10-38](https://user-images.githubusercontent.com/77655812/189487826-ebb8d97a-99ef-4c15-85ae-23a5adcd6590.png)






