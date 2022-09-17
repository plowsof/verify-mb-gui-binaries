[virusTotal detectioins](#virustotal-results)
### Question:

Given a zip full of signed .exe files , can we prove that they are indeed the original Monero Binaries? Join me

Signed binaries should stop antiviruses from deleting Monero related files.    

### TLDR

These are indeed signed Monero binaries - but with trailing zeros after signature is removed and an incorrect internal checksum value (which is just a string, not a real checksum), which once corrected, gives us a file identical to the original. I show this with a workflow script [output here](https://github.com/plowsof/verify-mb-gui-binaries/runs/8285192387?check_suite_focus=true)

MajesticBank has paid for these binaries to be signed (2~3kusd) and will be providing a download link. I am temporarily hosting them @ https://p2pcrowd.fund/monero-gui-v18.1.0.zip until 2022/09/20 Official link: https://download.majesticbank.sc/monero-gui-v0.18.1.0.zip

confirm the sha256sum is the same as i've pgp signed (in hash.txt or scroll to bottom)

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

Opening `monero.exe.nosig.nozero` in PE-Bear (a tool for reversing Packaged Executible files) we see that the reason the original monerod.exe and monerod.exe.nosig.nozero differ is because of an internal checksum value (highlighted red because it is incorrect) - our new file with no signature and trailing zeros removed is identical to the official monerod.exe , we just have to change the string value of this checksum to be correct (the same of the original).    
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

In the workflow script , we can see the 06 -> 01 difference. The rest of the files have the same tiny diff because of the checksum value [here](https://github.com/plowsof/verify-mb-gui-binaries/runs/8285192387?check_suite_focus=true#step:7:55)

![Screenshot from 2022-09-10 15-10-38](https://user-images.githubusercontent.com/77655812/189487826-ebb8d97a-99ef-4c15-85ae-23a5adcd6590.png)

### Hash signed by Plowsof

my pub key at https://github.com/plowsof/pgp/blob/main/plowsof.asc
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

a30cd7524fa5a63742ce5af4b18f70268fa7b39d27be52389719764315db7a02  monero-gui-v0.18.1.0.zip

-----BEGIN PGP SIGNATURE-----

iI0EARMIADUWIQTci88MUIPyAweCgD5OipEtQO0FLAUCYxymUBcccGxvd3NvZkBw
cm90b25tYWlsLmNvbQAKCRBOipEtQO0FLPqYAQCYe+KBkcHOCA7h9+w3tWdxGtAV
izD9SgPuEPkf1568HwD8D3dTR4EU82ZMqyVmyZdE///WTCmKG5Ks3CVB3smPp6Y=
=N8v/
-----END PGP SIGNATURE-----

```


### VirusTotal results

| Filename | non-signed | signed |
| --- | --- | --- |
| monero-blockchain-import.exe | [30](https://www.virustotal.com/gui/file/cdc39cca213e920625617b09dcd5b4c73d6c81413ada4e27f91051e112ebec4f/detection) | [19](https://www.virustotal.com/gui/file/6577728de8ce52598c8905dcb3fce439186ab92ce2d65275cd0453262028c749/detection) |
| monero-wallet-cli.exe | [13](https://www.virustotal.com/gui/file/2ee5e5a9a8026c9497dd31e2dcb2f81770a55ddcfea3c9a7a54089a156cf0b4c/detection) | [12](https://www.virustotal.com/gui/file/fda2958615a739f4c5c8015314c2dddefc357dc6d9a8ba0563846e9a546d8ba0/detection) |
| monero-blockchain-prune-known-spent-data.exe | [31](https://www.virustotal.com/gui/file/31a119d6d543670d2b6b708958cb57140aa1a62ccfc3875befa1aa8149587533/detection) | [0](https://www.virustotal.com/gui/file/c9b241f4c27fd3e84c768696103cbb0570621113ef96531862761ea088bbb420/detection) |
| monero-blockchain-depth.exe | [34](https://www.virustotal.com/gui/file/b0fd634e37aadfdf875841491bf017daff25bb11ca02e18f6e2898d6535d2d96/detection) | [23](https://www.virustotal.com/gui/file/20fdfd2b0e40525a1d745bb541b0bda507603e37cae694e8b82891ee275aaed1/detection) |
| monero-blockchain-stats.exe | [31](https://www.virustotal.com/gui/file/b7098e9b81d4e6ae0aa488581b090d6d2224df2a4a0c5d5b05cd9ef302fef010/detection) | [21](https://www.virustotal.com/gui/file/6c3ee308c91c3bbcaf77b6ace023447fbaa6103a71919e8fa63973ce496ff4ad/detection) |
| monero-blockchain-ancestry.exe | [29](https://www.virustotal.com/gui/file/792ba39746c2a82630aa60ac56e62673e95e3c30aa055f373110a823e544b338/detection) | [24](https://www.virustotal.com/gui/file/950fb1bda7b9f573c61113ecdefbdac58e89554a6837b37a3f95160889a5f72e/detection) |
| monero-wallet-rpc.exe | [15](https://www.virustotal.com/gui/file/de75419d1659dc71a6fda132d6a6b62bdbadf296ed3cafad397731dd4925b325/detection) | [12](https://www.virustotal.com/gui/file/1a549fc343cec1f2767ea271c474653a8a421e7daf731abcd816ef60927bb3f1/detection) |
| monero-gen-trusted-multisig.exe | [16](https://www.virustotal.com/gui/file/a61fb96921b3647f8952f963828f4d11fec419929466d95d476e55928b0cb6f1/detection) | [13](https://www.virustotal.com/gui/file/792e6492eff49160c9db1be2fff8fa7fbd7c338d72d5222a1559574115fd26d6/detection) |
| monero-wallet-gui.exe | [4](https://www.virustotal.com/gui/file/aa1236e8ff94e1e698b88f960dc084448dfeea52ce5247b3d6fedab17194027f/detection) | [0](https://www.virustotal.com/gui/file/a261b3d12ef102d8fd302d969e72e8c91bf8c42762ad18be8374f5219e3ae4de/detection) |
| monero-blockchain-usage.exe | [33](https://www.virustotal.com/gui/file/b7b9b084ef31ceda8d49e627ad7e21f9fb01c871d81d68ca30223f5392571acb/detection) | [22](https://www.virustotal.com/gui/file/d02044d86e981c2c9d62450ca617f3af56be16777b0eb8cde488ee116fc577af/detection) |
| monero-blockchain-mark-spent-outputs.exe | [21](https://www.virustotal.com/gui/file/dad8c91d84f3d941c4cad203efd7037685ca33b3bdae6b0fb5b181614ba53bef/detection) | [15](https://www.virustotal.com/gui/file/e2924934ce6f170fcc1ecec588b70c82447a490246ed7125f2e97d0922d750e3/detection) |
| monerod.exe | [27](https://www.virustotal.com/gui/file/42e2ad50112d8dfb1bb3053707fd2696d57fe4c40a33702a14ff99138d8f519b/detection) | [22](https://www.virustotal.com/gui/file/453c8acf34245d9259791d290b5b12f8a429264561fefc7325029fe3e22c4683/detection) |
| monero-blockchain-export.exe | [21](https://www.virustotal.com/gui/file/7799b6c788c3732ce3dc53cb120a9ae664382085471c0b100b962db4c2f8f4e3/detection) | [17](https://www.virustotal.com/gui/file/db316c3a71823c168b64bb696a3c7ac4006eb7a4f26f1666baf904b7e7f735b0/detection) |
| monero-gen-ssl-cert.exe | [0](https://www.virustotal.com/gui/file/7f285310497a056a1a6b67bae29ce0ff0c5326020175aaadee90a4e120585d5c/detection) | [0](https://www.virustotal.com/gui/file/3ed68f49afaf5940f7bed53c5c6cd5a7c7d3609101669b7dec8f65f199018c65/detection) |
| monero-blockchain-prune.exe | [34](https://www.virustotal.com/gui/file/91052037b62673104b26b1c195668a81b174905bda59d9f22d7f107678d1254a/detection) | [23](https://www.virustotal.com/gui/file/fcd079dc9deee35b61a7134c33d9d2681998d34af8d38f2dd4e6a4e1e9a708e0/detection) |
