---
TOCTitle: Tabelle di base del database di configurazione RMS
Title: Tabelle di base del database di configurazione RMS
ms:assetid: '8f9e15a2-92bc-41f7-a4fd-329567afb142'
ms:contentKeyID: 18824694
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747676(v=WS.10)'
---

Tabelle di base del database di configurazione RMS
==================================================

Nel presente argomento, vengono descritte le tabelle di base del database di configurazione di RMS.

DRMS\_ApplicationExclusionList
------------------------------

Nella tabella seguente, sono elencate le informazioni sulle applicazioni escluse.

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
<td style="border:1px solid black;"><p>ID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Nome</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome dell'applicazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VersionMinMajor</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione principale minimo dell'applicazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>VersionMinMinor</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione secondario minimo dell'applicazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VersionMinBuild</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione della build minimo dell'applicazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>VersionMinRevision</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione della revisione minimo dell'applicazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VersionMaxMajor</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione principale massimo dell'applicazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>VersionMaxMinor</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione secondario massimo dell'applicazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VersionMaxBuild</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione della build massimo dell'applicazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>VersionMaxRevision</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero di versione della revisione massimo dell'applicazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Descrizione</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Descrizione dell'applicazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_AsynchronousQueue  
-----------------------
  
Nella tabella seguente, sono elencate le informazioni relative alla coda di messaggi.
  
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
<td style="border:1px solid black;"><p>AsyncQueueID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>QueueName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Percorso della coda di messaggi</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_CaType  
------------
  
Nella tabella seguente, sono elencate le informazioni sul tipo di certificato emesso per il client.
  
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
<td style="border:1px solid black;"><p>ID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>ID del certificato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>TypeName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Desktop, MobileDevice o Server</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_ClusterConfiguration  
--------------------------
  
Nella tabella seguente, sono elencate le informazioni sul certificato concessore di licenze server in uso, incluso nella tabella DRMS\_LicensorCertificate.
  
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
<td style="border:1px solid black;"><p>CurrentLicensorCertID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Certificato concessore di licenze attivo</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_ClusterPolicies  
---------------------
  
Nella tabella seguente, sono elencate le informazioni sui percorsi in cui sono memorizzati i criteri del cluster.
  
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
<td style="border:1px solid black;"><p>PolicyID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>ID del criterio</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PolicyName</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome del criterio</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>PolicyData</p></td>
<td style="border:1px solid black;"><p>sql_variant</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Dati del criterio</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_ClusterServer  
-------------------
  
Nella tabella seguente, sono elencate le informazioni sui server presenti nel cluster.
  
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
<td style="border:1px solid black;"><p>ServerID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>ID del server</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ServerName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non specificato</p></td>
<td style="border:1px solid black;"><p>Nome del computer per il server</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_GICExclusionList  
----------------------
  
Nella tabella seguente, sono elencate le informazioni sui certificati per account con diritti esclusi.
  
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
<td style="border:1px solid black;"><p>PublicKeyIndex</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PublicKey</p></td>
<td style="border:1px solid black;"><p>PublicKey</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Byte della chiave pubblica</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>UserID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Indice ID utente</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ExpirationDate</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Data di scadenza del certificato per account con diritti</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Descrizione</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>NOME associato alla chiave del certificato per account con diritti escluso</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_LicensorCertificate  
-------------------------
  
Nella tabella seguente, sono elencate le informazioni relative al certificato concessore di licenze server attivo.
  
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
<td style="border:1px solid black;"><p>i_CertID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>ID del criterio</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>s_CertGUIDType</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di ID della coppia di chiavi</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>s_CertGUID</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>GUID ID della coppia di chiavi</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i_CertificateID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Puntatore al certificato effettivo</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_LicensorPrivateKey  
------------------------
  
Nella tabella seguente, sono elencate le informazioni sulla chiave privata del certificato concessore di licenze server attivo.
  
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
<td style="border:1px solid black;"><p>PrivateKeyID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CertGUIDType</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di ID della coppia di chiavi</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CertGUID</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>GUID ID della coppia di chiavi</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PrivateKey</p></td>
<td style="border:1px solid black;"><p>varbinary(2048)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Rappresentazione binaria della chiave</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CSP</p></td>
<td style="border:1px solid black;"><p>nvarchar(512)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Nome del provider del servizio di crittografia (CSP)</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CSPType</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di CSP</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>KeyContainerName</p></td>
<td style="border:1px solid black;"><p>nvarchar(512)</p></td>
<td style="border:1px solid black;"><p>Non specificato</p></td>
<td style="border:1px solid black;"><p>Nome del contenitore della chiave</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>KeyNumber</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Numero della chiave</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_PassportDenyList  
----------------------
  
Nella tabella seguente, sono elencate le informazioni sugli account Microsoft® .NET Passport a cui non devono essere concesse le licenze.
  
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
<td style="border:1px solid black;"><p>DenyID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DenyAddressPattern</p></td>
<td style="border:1px solid black;"><p>nvarchar(500)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome utente/Nome dominio</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_Plugin  
------------
  
Nella tabella seguente, sono elencate le informazioni relative ai plug-in.
  
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
<td style="border:1px solid black;"><p>PluginID</p></td>
<td style="border:1px solid black;"><p>Int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PluginTypeID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di plug-in</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>NameSpace</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Spazio dei nomi per il plug-in</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PluginName</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome del plug-in</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Ordinal</p></td>
<td style="border:1px solid black;"><p>Int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Numero sequenziale relativo all'esecuzione del plug-in</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Path</p></td>
<td style="border:1px solid black;"><p>nvarchar(512)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Percorso del file DLL</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ObjectTypeName</p></td>
<td style="border:1px solid black;"><p>nvarchar(50)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Non utilizzato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DebugMode</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Valore che indica se eseguire un plug-in in modalità di debug</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>PublicKey</p></td>
<td style="border:1px solid black;"><p>PublicKey</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Chiave pubblica del plug-in</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Version</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Versione del plug-in</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_AllowedPluginVersions  
---------------------------
  
Nella tabella seguente, sono elencate le informazioni sulle versioni di plug-in a cui è concessa la partecipazione al sistema RMS.
  
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
<td style="border:1px solid black;"><p>RowID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PluginID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VersionInfo</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>Non specificato</p></td>
<td style="border:1px solid black;"><p>Versione del plug-in</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_PluginProperties  
----------------------
  
Nella tabella seguente, sono elencate le informazioni relative alle proprietà dei plug-in.
  
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
<td style="border:1px solid black;"><p>PropertyID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PluginID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>ID del plug-in a cui appartiene la proprietà</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>PropertyName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome della proprietà per i dati di configurazione</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PropertyValue</p></td>
<td style="border:1px solid black;"><p>text</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Valore della proprietà per i dati di configurazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_PluginType  
----------------
  
Nella tabella seguente, sono elencate le informazioni relative al tipo di plug-in.
  
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
<td style="border:1px solid black;"><p>PluginTypeID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>PluginTypeName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome del plug-in</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_RightsTemplate  
--------------------
  
Nella tabella seguente, sono elencate le informazioni relative ai modelli di criteri per i diritti.
  
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
<td style="border:1px solid black;"><p>Guid</p></td>
<td style="border:1px solid black;"><p>nvarchar(128) (PK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>GUID del modello di criteri per i diritti</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>TemplateData</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Questo campo contiene i dati del modello XrML.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_TrustedCertificateAuthorities  
-----------------------------------
  
Nella tabella seguente sono elencate le informazioni relative alle autorità di certificazione trusted.
  
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
<td style="border:1px solid black;"><p>ID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(1,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CertificateID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>ID del certificato</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CertificateGUID</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>GUID del certificato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CaTypeID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di autorità di certificazione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_TrustedEmailDomains  
-------------------------
  
Nella tabella seguente sono elencate le informazioni relative ai domini di posta elettronica considerati trusted nell'ambiente RMS.
  
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
<td style="border:1px solid black;"><p>ID</p></td>
<td style="border:1px solid black;"><p>int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i_TrustedIdentityDomainID</p></td>
<td style="border:1px solid black;"><p>int (FK)t</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>s_EmailDomainName</p></td>
<td style="border:1px solid black;"><p>nvarchar(256)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Elenco dei nomi dei domini di posta elettronica validi per il dominio utenti trusted</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_TrustedIdentityDomain  
---------------------------
  
Nella tabella seguente, sono elencate le informazioni relative ai domini utente trusted e ai domini di pubblicazione trusted.
  
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
<td style="border:1px solid black;"><p>i_TrustedIdentityDomainID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>s_DomainType</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di dominio</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CertGUIDType</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di GUID del certificato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CertGUID</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>GUID del certificato</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_CertificateID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>ID del certificato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>i_allowSID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>SID del dominio</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>S_friendlyname</p></td>
<td style="border:1px solid black;"><p>nvarchar(255)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Nome descrittivo del certificato</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>dt_DateUpdated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp aggiornamento</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>dt_DateCreated</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Timestamp creazione</p></td>
</tr>  
</tbody>  
</table>
  
DRMS\_XrML\_Certificate  
-----------------------
  
Nella tabella seguente, sono elencate le informazioni relative ai certificati concessori di licenze server XrML a cui viene fatto riferimento nella tabella DRMS\_LicensorCertificate. Viene inoltre definita la catena di certificati.
  
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
<td style="border:1px solid black;"><p>i_CertificateID</p></td>
<td style="border:1px solid black;"><p>Int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Puntatore al certificato effettivo</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>s_Certificate</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Puntatore al certificato effettivo</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>i_ParentCertificateID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Puntatore al certificato effettivo</p></td>
</tr>  
</tbody>  
</table>
