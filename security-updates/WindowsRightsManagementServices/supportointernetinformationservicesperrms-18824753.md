---
TOCTitle: Supporto Internet Information Services per RMS
Title: Supporto Internet Information Services per RMS
ms:assetid: 'bd4dc69f-1e4e-4e95-9ae2-c925d8a14d4c'
ms:contentKeyID: 18824753
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747649(v=WS.10)'
---

Supporto Internet Information Services per RMS
==============================================

I servizi RMS principali vengono rilasciati mediante un insieme di servizi Web .NET ASP. Questi servizi Web vengono eseguiti in Microsoft® Internet Information Services (IIS). Durante il processo di provisioning del server, RMS configura alcune directory virtuali in IIS. I file di applicazione per i servizi Web vengono installati nelle directory virtuali.

Durante il provisioning del server, è possibile selezionare il sito Web in cui si desidera configurare le directory virtuali da un elenco di siti Web esistenti nel server. Prima di eseguire il provisioning di un server, può essere utile creare uno speciale sito Web per RMS. In tal caso, è possibile configurare autenticazione e limitazioni di accesso specifiche del sistema RMS.

Per impostazione predefinita, i file e le directory virtuali del servizio Web sono protette mediante l'elenco DACL (Discretionary Access Control List) per impedire accessi non autorizzati alle proprie funzionalità. Le voci ACE (Access Control Entries) di questi elementi sono le seguenti:

-   Al gruppo di amministratori è assegnato un controllo completo
-   Al sistema locale è assegnato un controllo completo
-   Al gruppo del servizio RMS sono assegnate le autorizzazioni di lettura ed esecuzione
-   Agli utenti Guest e normali sono assegnate le autorizzazioni di lettura ed esecuzione, elenco del contenuto delle cartelle e lettura
-   L'accesso anonimo non è consentito

Nella tabella seguente vengono elencate le directory virtuali create in IIS e i servizi installati in tali directory.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th>Directory virtuale</th>
<th>Servizio</th>
<th>File servizio Web</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>_wmcs</p></td>
<td style="border:1px solid black;"><p>Questa è la directory virtuale per l'amministrazione dei cluster RMS</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Certification</p></td>
<td style="border:1px solid black;"><p>Questa directory virtuale contiene i servizi che supportano la certificazione di RMS</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Proxy di attivazione</p></td>
<td style="border:1px solid black;"><p>Activation.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Certificazione degli account</p></td>
<td style="border:1px solid black;"><p>Certification.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Pre-certificazione</p></td>
<td style="border:1px solid black;"><p>Precertification.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Rilevamento di servizi</p></td>
<td style="border:1px solid black;"><p>ServiceLocator.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Server</p></td>
<td style="border:1px solid black;"><p>Server.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Certificazione server</p></td>
<td style="border:1px solid black;"><p>ServerCertification.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Certificazione dispositivi mobili</p></td>
<td style="border:1px solid black;"><p>MobileDeviceCertfication.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Registrazione</p></td>
<td style="border:1px solid black;"><p>SubEnrollService.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Gestione delle licenze</p></td>
<td style="border:1px solid black;"><p>Questa directory virtuale contiene i servizi che supportano la gestione delle licenze di RMS</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Gestione delle licenze</p></td>
<td style="border:1px solid black;"><p>License.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Pubblicazione</p></td>
<td style="border:1px solid black;"><p>Publish.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Server</p></td>
<td style="border:1px solid black;"><p>Server.asmx</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Rilevamento di servizi</p></td>
<td style="border:1px solid black;"><p>ServiceLocator.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Admin</p></td>
<td style="border:1px solid black;"><p>Questa directory virtuale contiene i servizi che supportano l'amministrazione di RMS</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Amministrazione</p></td>
<td style="border:1px solid black;"><p>AdminSvc.asmx</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DrmRemote</p></td>
<td style="border:1px solid black;"><p>Interfaccia di .NET Remoting</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>DirectoryServices</p></td>
<td style="border:1px solid black;"><p>Questa è una sottodirectory di DrmRemote</p></td>
<td style="border:1px solid black;"><p>Non applicabile</p></td>
</tr>  
</tbody>  
</table>
  
| ![](images/Cc747649.note(WS.10).gif)Nota                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |  
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| Il servizio di amministrazione prevede maggiori restrizioni rispetto agli altri servizi Web perché le interfacce disponibili consentono di configurare RMS. Di conseguenza, i membri del gruppo di utenti non possono accedere al servizio di amministrazione. Inoltre, è attivato il filtraggio IP per consentire l'accesso solo al computer locale. La directory virtuale DirectoryServices non consente l'accesso agli utenti Guest. Il servizio di rilevamento dei servizi consente inoltre un controllo completo all'account Servizio di rete. Per eseguire il provisioning di un server licenze, è necessario modificare le voci ACE predefinite in modo da consentire l'accesso da parte dell'amministratore di RMS. |
