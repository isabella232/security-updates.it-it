---
TOCTitle: Tabelle delle certificazioni del database di configurazione RMS
Title: Tabelle delle certificazioni del database di configurazione RMS
ms:assetid: 'd392663a-1a46-42f6-a71d-f0f2c1843566'
ms:contentKeyID: 18824789
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747760(v=WS.10)'
---

Tabelle delle certificazioni del database di configurazione RMS
===============================================================

Nel presente argomento, vengono descritte le tabelle di certificazione del database di configurazione di RMS. Nelle tabelle sono incluse informazioni sui certificati per account con diritti emessi per gli utenti dell'installazione.

UD\_Machines
------------

Nella tabella seguente, sono elencate le informazioni relative agli ID hardware di tutti i computer.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="25%" />
<col width="25%" />
<col width="25%" />
<col width="25%" />
</colgroup>
<thead>
<tr class="header">
<th>Nome</th>
<th>Tipo di dati</th>
<th>Valori NULL</th>
<th>Descrizione</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>i_MachineId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(1,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>b_PubKeyHash</p></td>
<td style="border:1px solid black;"><p>binary(20)</p></td>
<td style="border:1px solid black;"><p>(20) Non NULL</p></td>
<td style="border:1px solid black;"><p>Hash dell'ID hardware</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_CreateDate</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora dell'aggiunta della voce alla tabella</p></td>
</tr>  
</tbody>  
</table>
  
UD\_PassportAuthIdentities  
--------------------------
  
Nella tabella seguente, sono elencate le informazioni relative alle informazioni di Microsoft® .NET Passport per gli utenti.
  
###  

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th>Nome</th>  
<th>Tipo di dati</th>  
<th>Valori NULL</th>  
<th>Descrizione</th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_UserId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i64_Puid</p></td>
<td style="border:1px solid black;"><p>bigint</p></td>
<td style="border:1px solid black;"><p>(50) NULL</p></td>
<td style="border:1px solid black;"><p>ID utente di .NET Passport</p></td>
</tr>  
</tbody>  
</table>
  
UD\_UserMachine  
---------------
  
Nella tabella seguente, gli utenti certificati sono messi in relazione con le informazioni corrispondenti sul computer.
  
###  

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th>Nome</th>  
<th>Tipo di dati</th>  
<th>Valori NULL</th>  
<th>Descrizione</th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_MachineId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i_UserId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_CreateDate</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora dell'aggiunta della voce alla tabella</p></td>
</tr>  
</tbody>  
</table>
  
UD\_Users  
---------
  
Nella tabella seguente, sono elencate le informazioni relative ai dati utente.
  
###  

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th>Nome</th>  
<th>Tipo di dati</th>  
<th>Valori NULL</th>  
<th>Descrizione</th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_UserId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(1,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>b_KeyData</p></td>
<td style="border:1px solid black;"><p>varbinary(2000)</p></td>
<td style="border:1px solid black;"><p>(2000) Non NULL</p></td>
<td style="border:1px solid black;"><p>Chiave privata/pubblica dell'utente crittografata</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_KeyDataLength</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Lunghezza della chiave privata/pubblica non crittografata</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>b_PublicKey</p></td>
<td style="border:1px solid black;"><p>PublicKey</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Chiave pubblica dell'utente</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_EncryptionDbId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice al certificato concessore di licenze utilizzato per crittografare la coppia chiave privata/pubblica</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>s_Certificate</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>Non specificato</p></td>
<td style="border:1px solid black;"><p>Non utilizzato</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_Expiration</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data di scadenza della chiave dell'utente</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_TemporaryExpiration</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora di scadenza per l'utilizzo temporaneo della chiave</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>f_Modified</p></td>
<td style="border:1px solid black;"><p>bit</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Non utilizzato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i_Quota</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Livello corrente della quota per l'utente</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_WaitDays</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Numero di giorni prima che le richieste di quote aggiuntive vengano accettate</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_LastConsumption</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora dell'ultima certificazione utente aggiuntiva</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_CreateDate</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora dell'aggiunta della voce alla tabella</p></td>
</tr>  
</tbody>  
</table>
  
UD\_Windows AuthIdentities  
--------------------------
  
Nella tabella seguente, vengono elencati gli ID di tutti gli utenti certificati e autenticati Windows.
  
###  

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
<col width="25%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th>Nome</th>  
<th>Tipo di dati</th>  
<th>Valori NULL</th>  
<th>Descrizione</th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_UserId</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>s_Sid</p></td>
<td style="border:1px solid black;"><p>Sid</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>ID di protezione (SID) dell'utente</p></td>
</tr>  
</tbody>  
</table>
