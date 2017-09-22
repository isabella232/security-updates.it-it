---
TOCTitle: Visualizzazione dei file di registro
Title: Visualizzazione dei file di registro
ms:assetid: '2dc9ed54-76d8-4721-ba93-194845de726a'
ms:contentKeyID: 18824541
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc720228(v=WS.10)'
---

Visualizzazione dei file di registro
====================================

In funzione del modo in cui è stato distribuito RMS, i file di registrazione attività sono registrati in un server di database come SQL Server o Microsoft SQL Server 2000 Desktop Engine (MSDE 2000) Versione A. È possibile scrivere dei filtri per ridurre le informazioni archiviate nei file di registrazione attività. Per informazioni, vedere la Guida di SQL Server Enterprise Manager.

La dimensione di una voce di registro tipica è di circa 300 byte. Nella tabella seguente, vengono descritti i campi registrati.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Campo</th>
<th>Descrizione</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>HostMachineName</p></td>
<td style="border:1px solid black;"><p>Computer che ha gestito la richiesta.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>HostMachineRequestId</p></td>
<td style="border:1px solid black;"><p>Identificatore univoco della richiesta nel computer. La combinazione di HostMachineName e HostMachineRequestId consente di identificare in modo univoco la richiesta nel cluster.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>RequestTime</p></td>
<td style="border:1px solid black;"><p>Ora standard (UTC o ora di Greenwich) di ricezione della richiesta.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>RequestPath</p></td>
<td style="border:1px solid black;"><p>URL relativo del file con estensione asmx, ad esempio: /_wmcs/licensing/License.asmx.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>RequestType</p></td>
<td style="border:1px solid black;"><p>Nome del metodo Web richiamato, ad esempio: AcquireLicense.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>RequestUserAddress</p></td>
<td style="border:1px solid black;"><p>Indirizzo IP di origine del richiedente.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>RequestUserAgent</p></td>
<td style="border:1px solid black;"><p>Valore agente utente dell'intestazione HTTP.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>AuthenticatedState</p></td>
<td style="border:1px solid black;"><p>Indicazione del fatto che la connessione HTTP sia o meno autenticata (True/False).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>SecureConnectionState</p></td>
<td style="border:1px solid black;"><p>Indicazione del fatto che si tratti di una connessione SSL (True/False).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>AuthenticatedId</p></td>
<td style="border:1px solid black;"><p>Nome di accesso per le richieste autenticate. Vuoto se AuthenticatedState=False.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ReceivedXrMLDocument</p></td>
<td style="border:1px solid black;"><p>Documento XrML ricevuto dal richiedente.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ReceivedXrMLDocumentIssuerChain</p></td>
<td style="border:1px solid black;"><p>Catena emittente del documento XrML ricevuto.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>IssuedXrMLDocument</p></td>
<td style="border:1px solid black;"><p>Documento XrML restituito al richiedente.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>IssuedXrMLDocumentIssuerChain</p></td>
<td style="border:1px solid black;"><p>Catena emittente del documento XrML emesso.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>SuccessOrFailure</p></td>
<td style="border:1px solid black;"><p>Indicazione del fatto che la richiesta sia stata elaborata correttamente o abbia generato un errore.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Metadata</p></td>
<td style="border:1px solid black;"><p>Campo Metadati.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ErrorInformation</p></td>
<td style="border:1px solid black;"><p>Messaggio di errore descrittivo, nel caso in cui si verifichi un errore.</p></td>
</tr>  
</tbody>  
</table>
