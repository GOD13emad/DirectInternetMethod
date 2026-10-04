$ErrorActionPreference='Stop'
$items=@(
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_hotfix121\delivery\DirectInternetMethod_1.2.1_Windows_Setup.exe';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.2.1_Windows_Setup.exe';Sha='B0CFFC657FC53888954CBE16E63276EE597BD96C57D1FFA7F75A289BE56C28BA'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_hotfix121\delivery\DirectInternetMethod_1.2.1_Linux_x86_64.zip';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.2.1_Linux_x86_64.zip';Sha='CAF93659623A5A88DB4ED182B2F6C2EF1E7E1DDC94534896ABB09883EFC25A65'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_ui131\delivery\DirectInternetMethod_1.3.1_Windows_Setup.exe';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.3.1_Windows_Setup.exe';Sha='4F70C372E6B8CE7152D9501E5C4A70F4B2F650638CFDD3014B18EB6E3C123093'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_ui131\delivery\DirectInternetMethod_1.3.1_Linux_x86_64.zip';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.3.1_Linux_x86_64.zip';Sha='B21BD0D5C8B40643F4CF5F07DC13F220B07E71A674F862DFB792D63FD9823A34'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_provider131\delivery\DirectInternetMethod_1.3.2_Windows_Setup.exe';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.3.2_Windows_Setup.exe';Sha='B5141A93BDF2C261F54F4C0483128D973A54DEFBCD45C6C701535037B31E6E58'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_provider131\delivery\DirectInternetMethod_1.3.2_Linux_x86_64.zip';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.3.2_Linux_x86_64.zip';Sha='8D4AB63AC64CF1837C47341D2438617BDF821919AE170BA75B301AA2B661172D'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140\delivery\DirectInternetMethod_1.4.0_Windows_Setup.exe';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.4.0_Windows_Setup.exe';Sha='69F0EF63E3A658EC616362FC7D7ADAB95337EC3A034D3981DF44C685DB9FCB93'},
 [pscustomobject]@{Source='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140\delivery\DirectInternetMethod_1.4.0_Linux_x86_64.zip';Dest='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.4.0_Linux_x86_64.zip';Sha='4CF521FD3821F9204999C0F17B217A60DC7117AC68421E5634FDF8D15D3C485E'}
)
$out=@()
foreach($i in $items){
 if(-not(Test-Path -LiteralPath $i.Source)){throw "SOURCE_MISSING $($i.Source)"}
 $sh=(Get-FileHash -LiteralPath $i.Source -Algorithm SHA256).Hash
 if($sh -ne $i.Sha){throw "SOURCE_HASH_MISMATCH $($i.Source) $sh"}
 Copy-Item -LiteralPath $i.Source -Destination $i.Dest -Force
 $dh=(Get-FileHash -LiteralPath $i.Dest -Algorithm SHA256).Hash
 if($dh -ne $i.Sha){throw "DEST_HASH_MISMATCH $($i.Dest) $dh"}
 $out += [pscustomobject]@{Source=$i.Source;Destination=$i.Dest;Sha256=$dh;Bytes=(Get-Item -LiteralPath $i.Dest).Length}
}
$sumSrc='C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140\delivery\SHA256SUMS.txt'
$sumExpected='7F80836A153EF0FFEF1A79D797502B773D8776DB99BBE21E1D81227A2D9EA609'
if((Get-FileHash -LiteralPath $sumSrc -Algorithm SHA256).Hash -ne $sumExpected){throw 'PUBLIC_SUM_SOURCE_HASH_MISMATCH'}
Copy-Item -LiteralPath $sumSrc -Destination 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\SHA256SUMS.txt' -Force
$sumHash=(Get-FileHash -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\SHA256SUMS.txt' -Algorithm SHA256).Hash
if($sumHash -ne $sumExpected){throw 'PUBLIC_SUM_DEST_HASH_MISMATCH'}
$out += [pscustomobject]@{Source=$sumSrc;Destination='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\SHA256SUMS.txt';Sha256=$sumHash;Bytes=(Get-Item -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\SHA256SUMS.txt').Length}
$out|ConvertTo-Json -Depth 4|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\ARTIFACT_CONSOLIDATION_MANIFEST.json' -Encoding utf8
"PASS_ARTIFACT_CONSOLIDATION=$($out.Count)"
