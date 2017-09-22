---
TOCTitle: Servizi Web RMS
Title: Servizi Web RMS
ms:assetid: 'ed8dbb2e-0590-4502-afc4-54f66b96d515'
ms:contentKeyID: 18824825
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747728(v=WS.10)'
---

Servizi Web RMS
===============

RMS fornisce il componente server di un sistema RMS. Le funzioni di base di tale componente vengono implementate come insieme di servizi Web Microsoft® ASP.NET eseguiti su Microsoft® Internet Information Services (IIS). I servizi Web RMS vengono esposti tramite l'interfaccia SOAP o tramite Servizi remoti .NET.

I servizi Web forniscono:

-   Registrazione secondaria di server
-   Certificazione account di entità attendibili
-   Licenze per l'utilizzo di informazioni protette con RMS
-   Funzioni di amministrazione di RMS

Nella tabella riportata di seguito vengono descritti i servizi Web RMS.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Servizio</th>
<th>Descrizione</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Registrazione secondaria</p></td>
<td style="border:1px solid black;"><p>Fornisce certificati concessori di licenze server subordinati ai server nei cluster utilizzati esclusivamente per la gestione delle licenze. Questi certificati consentono al cluster utilizzato esclusivamente per la gestione delle licenze di rilasciare licenze d'uso e di pubblicazione.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Certificazione account</p></td>
<td style="border:1px solid black;"><p>Fornisce certificati per account con diritti agli utenti. Questi certificati sono necessari per gli utenti per ottenere licenze d'uso e di pubblicazione in modo da creare e utilizzare contenuti protetti con RMS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Proxy di attivazione</p></td>
<td style="border:1px solid black;"><p>Questo servizio garantisce la compatibilità con il client RMS versione 1. Consente di passare le richieste di attivazione del computer al servizio di attivazione Microsoft e di restituire gli archivi protetti e i certificati del computer RMS ai client RMS versione 1. Questo servizio non viene utilizzato dai client RMS con Service Pack 1 (SP1) o versioni successive.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Pubblicazione</p></td>
<td style="border:1px solid black;"><p>Consente di rilasciare licenze di pubblicazione che consentono agli autori di creare e distribuire contenuti protetti con RMS. Consente inoltre di rilasciare certificati concessori di licenze client, che consentono agli utenti di pubblicare contenuti protetti con RMS senza essere connessi alla rete interna che ospita RMS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Gestione licenze</p></td>
<td style="border:1px solid black;"><p>Consente di rilasciare licenze d'uso, che permettono agli utenti di utilizzare il contenuto protetto con RMS.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Amministrazione</p></td>
<td style="border:1px solid black;"><p>Consente all'amministratore di gestire RMS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DrmRemote</p></td>
<td style="border:1px solid black;"><p>Consente ai servizi Web di comunicare tra loro e con altri componenti del sistema RMS esponendo Servizi remoti .NET.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Rimozione autorizzazioni</p></td>
<td style="border:1px solid black;"><p>Consente di rimuovere la protezione del contenuto protetto in precedenza con RMS e di restituirlo al client. Questo servizio viene installato dal programma di installazione di RMS ma non dispone di una radice virtuale corrispondente in IIS fino a quando non viene attivato dall'amministratore. L'attivazione di questo servizio determina la disattivazione di tutti gli altri servizi.</p></td>
</tr>  
</tbody>  
</table>
  
Oltre ai servizi Web, in RMS viene installato un servizio listener di registrazione attività. Ciascun servizio Web invia i dati registrati alla coda di messaggi di registrazione attività. Il servizio listener di registrazione attività quindi trasferisce i dati registrati dalla coda di messaggi al database di registrazione.
  
Le applicazioni dei servizi Web risiedono nelle directory virtuali di IIS. Queste directory virtuali vengono installate in ciascun server RMS nel sito selezionato durante il provisioning.
  
L'autenticazione e l'accesso vengono configurati separatamente per ciascuna directory virtuale. Inoltre, l'accesso viene configurato separatamente per ciascun servizio Web. Per informazioni sulle impostazioni di protezione nelle directory virtuali e nei file dei servizi Web, vedere [Supporto Internet Information Services per RMS](https://technet.microsoft.com/bd4dc69f-1e4e-4e95-9ae2-c925d8a14d4c) più avanti in questo argomento.
  
Per ulteriori informazioni su ciascun servizio Web, vedere la sezione relativa ai [Componenti software di RMS](https://technet.microsoft.com/e38a840e-f390-48fd-8354-50108a64f5ca) più avanti in questo argomento.
