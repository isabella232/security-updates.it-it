---
TOCTitle: Tabelle del database di registrazione RMS
Title: Tabelle del database di registrazione RMS
ms:assetid: '7ab2104c-b12d-4807-8a4b-bcabb145ff9b'
ms:contentKeyID: 18824663
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747569(v=WS.10)'
---

Tabelle del database di registrazione RMS
=========================================

Nella presente sezione vengono descritte le tabelle di registrazione attività del database di RMS.

DRMS\_Log\_Master
-----------------

Nella tabella seguente sono elencate le voci relative a ogni record di registrazione.

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
<td style="border:1px solid black;"><p>i_LogID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>ID univoco del record di registrazione</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_HostMachineName</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Server da cui è stato generato il record</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_HostMachineRequestId</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>ID della richiesta</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>dt_RequestTime</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Data e ora della richiesta</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_RequestPath</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Percorso URL della richiesta</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_RequestType</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Tipo di richiesta</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_RequestUserAddress</p></td>
<td style="border:1px solid black;"><p>nvarchar(32)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Indirizzo IP del client</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_RequestUserAgent</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Intestazione agente utente del client</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_AuthenticatedState</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Stato di autenticazione della richiesta</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_SecureConnectionState</p></td>
<td style="border:1px solid black;"><p>nvarchar(64)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Protezione SSL della richiesta</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_AuthenticatedId</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>ID dell'utente autenticato</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_ReceivedXrML</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>XrML ricevuto dal client nella richiesta</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_IssuedXrML</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Licenza XrML emessa nella richiesta</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_Metadata</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Metadata</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_SuccessOrFailure</p></td>
<td style="border:1px solid black;"><p>nvarchar(32)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Successo o insuccesso della richiesta</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_ErrorInformation</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Dati dell'errore</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>dt_LogCreateTime</p></td>
<td style="border:1px solid black;"><p>datetime</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Ora di creazione del registro</p></td>
</tr>
</tbody>
</table>
  
DRMS\_Log\_Detail  
-----------------
  
Nella tabella seguente, sono elencati ulteriori dati per un record di registrazione. I dati XrML vengono generalmente registrati in questa tabella.
  
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
<td style="border:1px solid black;"><p>i_LogDetailID</p></td>
<td style="border:1px solid black;"><p>int (PK)</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1)</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>i_LogID</p></td>
<td style="border:1px solid black;"><p>int (FK)</p></td>
<td style="border:1px solid black;"><p>Non NULL (FK)</p></td>
<td style="border:1px solid black;"><p>ID del record di registrazione padre</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_Name</p></td>
<td style="border:1px solid black;"><p>nvarchar(128)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome della proprietà</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_Value</p></td>
<td style="border:1px solid black;"><p>ntext</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Valore della proprietà</p></td>
</tr>
</tbody>
</table>
  
DRMS\_Log\_Filter  
-----------------
  
Nella tabella seguente, sono elencati i campi registrati dal servizio di registrazione attività.
  
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
<td style="border:1px solid black;"><p>i_ID</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>IDENTITY(100,1) Non NULL</p></td>
<td style="border:1px solid black;"><p>Indice interno</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>s_FieldName</p></td>
<td style="border:1px solid black;"><p>nvarchar(255)</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Nome del campo</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>s_FieldDescription</p></td>
<td style="border:1px solid black;"><p>nvarchar(1024)</p></td>
<td style="border:1px solid black;"><p>NULL</p></td>
<td style="border:1px solid black;"><p>Descrizione del campo</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>i_IsIncluded</p></td>
<td style="border:1px solid black;"><p>int</p></td>
<td style="border:1px solid black;"><p>Non NULL</p></td>
<td style="border:1px solid black;"><p>Valore che indica se il campo è registrato</p></td>
</tr>
</tbody>
</table>
