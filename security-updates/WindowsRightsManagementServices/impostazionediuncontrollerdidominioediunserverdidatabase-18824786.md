---
TOCTitle: Impostazione di un controller di dominio e di un server di database
Title: Impostazione di un controller di dominio e di un server di database
ms:assetid: 'd20f8305-9f9e-4760-bfbf-82824db60d1f'
ms:contentKeyID: 18824786
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747681(v=WS.10)'
---

Impostazione di un controller di dominio e di un server di database
===================================================================

Prima di installare un server di certificazione principale o un server licenze, assicurarsi di aver implementato il supporto appropriato di dominio e database utilizzando Active Directory e un server di database, come SQL Server 2000 con Service Pack 3 (SP3) o Microsoft® SQL Server 2000 Desktop Engine (MSDE 2000) Versione A. Anche se l'ambiente di produzione potrebbe già eseguire i componenti richiesti, si raccomanda di non utilizzare il proprio ambiente di produzione per i test.

Le procedure che seguono configurano un controller di dominio e un server di database su un unico computer di una rete isolata, per puro scopo di test del lato server.

| ![](images/Cc747681.note(WS.10).gif)Nota                                                                                                                                                                                                                                                                                                                    |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| In questo esempio, il server di database esegue il controller di dominio. In un ambiente di produzione in genere non è consigliabile ospitare altri componenti in un controller di dominio. Active Directory e il server di database, in questo esempio, sono installati sullo stesso computer per abilitare l'installazione dell'infrastruttura completa sul minimo numero di computer. |

Se si sceglie di utilizzare MSDE 2000 come server di database, si deve ricordare che questo non supporta alcuna interfaccia di rete e che i termini di utilizzo di MSDE 2000 specificano che non è possibile utilizzare gli strumenti client SQL Server per gestire un database MSDE. A causa di questa limitazione, non sarà possibile visualizzare informazioni sulla registrazione attività né modificare dati memorizzati nel database di configurazione. Si raccomanda quindi di utilizzare MSDE 2000 solo per supportare i database RMS negli ambienti di prova.

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
<th>Il componente infrastruttura</th>
<th>Procedura per la configurazione di un controller di dominio e di un server di database</th>
<th>Note per la distribuzione in un ambiente di produzione</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Sistema operativo</p></td>
<td style="border:1px solid black;"><p>Su un computer che soddisfa i requisiti hardware di RMS ma non è connesso a una rete, installare Windows 2000 Server con SP3 o successivo, oppure Windows Server 2003. Utilizzare il file system NTFS per la partizione.</p></td>
<td style="border:1px solid black;"><p>Si consiglia vivamente di installare sempre il service pack e gli aggiornamenti più recenti. Utilizzare partizioni formattate con NTFS.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Connessione di rete</p></td>
<td style="border:1px solid black;"><p>Stabilire una connessione a una rete che fornisca la connettività Internet ma sia isolata dall'ambiente di produzione.</p></td>
<td style="border:1px solid black;"><p>La connessione a Internet dovrebbe essere protetta con un firewall adeguato.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Indirizzo IP</p></td>
<td style="border:1px solid black;"><p>Assegnare un indirizzo IP statico a questo computer.</p></td>
<td style="border:1px solid black;"><p>Utilizzare sempre indirizzi IP statici per i server.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Active Directory</p></td>
<td style="border:1px solid black;"><p>Accedere come amministratore locale.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Fare clic su <strong>Start</strong>, fare clic su <strong>Esegui</strong>, digitare <code>dcpromo</code> nella casella <strong>Apri</strong>, quindi fare clic su <strong>OK</strong>.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Quando si avvia l'installazione guidata di Active Directory, seguire la procedura guidata per creare un nuovo dominio in un nuovo insieme di strutture, tranne per le seguenti opzioni:</p>
<p>Specificare il nome di dominio, ad esempio industrieharper.com.</p>  
<p>Lasciare che venga configurato automaticamente il servizio DNS nel computer.</p>  
<p>Selezionare <strong>Autorizzazioni compatibili soltanto con sistemi operativi server Windows 2000</strong> se tutti i controller di dominio eseguono Windows 2000 o versione successiva.</p>
<p>Fornire una password complessa per l'amministratore locale.</p></td>
<td style="border:1px solid black;"><p>Se sono richiesti nuovi domini per implementare RMS, configurarli in Active Directory.</p>
<p>Utilizzare sempre password complesse per tutti gli account.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Riavviare il computer quando viene richiesto.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Verificare il livello funzionale aprendo lo snap-in <strong>Utenti e computer di Active Directory</strong>, facendo clic con il pulsante destro del mouse sul nome del dominio, scegliendo <strong>Proprietà</strong>, quindi verificando l'impostazione nella casella <strong>Modalità di funzionamento del dominio</strong>. Se non sono presenti controller di dominio con sistema operativo precedente a Windows 2000, selezionare <strong>Cambia modalità</strong> per eseguire il dominio in <strong>Modalità originale</strong>.</p>
<p>Nota: In Windows Server 2003, l'impostazione <strong>Modalità di funzionamento del dominio</strong> è sostituita con <strong>Livello funzionalità dominio</strong>.</p></td>
<td style="border:1px solid black;"><p>Per ottimizzare al massimo la protezione e la gestibilità, è preferibile non utilizzare il livello funzionale misto di Windows 2000 per il supporto di RMS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Account utente</p></td>
<td style="border:1px solid black;"><p>Creare un account utente del dominio da utilizzare come account di servizio RMS per RMS, ad esempio HarperRMS@industrieharper.com. Specificare una password complessa. Assicurarsi di specificare un indirizzo di posta elettronica per l'utente. Se l'indirizzo di posta elettronica non è specificato in Active Directory, l'utente non sarà in grado di ottenere licenze e certificati da RMS.</p>
<p>Nota: L'account di servizio di RMS non può essere lo stesso account di dominio utilizzato per l'installazione di Windows RMS.</p></td>
<td style="border:1px solid black;"><p>Creare in Active Directory un account separato da utilizzare come account di servizio di RMS. Includere un indirizzo di posta elettronica. Non assegnare all'account autorizzazioni speciali.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>SQL Server 2000</p></td>
<td style="border:1px solid black;"><p>Accedere al server su cui si intende installare il database. Se questo server coincide con il controller di dominio, eseguire l'accesso come amministratore di dominio.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Seguire le istruzioni fornite con il software del database per installare il software del server di database.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Seguire le relative procedure ottimali per installare il server di database, ad esempio:</p>
<ul>  
<li>Fornire un nome per l'account dell'amministratore del sistema di database e un nome per l'organizzazione, ad esempio Harper.<br />  
<br />  
</li>  
<li>Fornire una password complessa per l'amministratore di sistema.<br />  
<br />  
</li>  
<li>Utilizzare i metodi di autenticazione integrati in Windows.<br />  
<br />  
</li>
</ul></td>
<td style="border:1px solid black;"><p>È consigliabile utilizzare un Modello di autenticazione Windows integrato. Se non è possibile eseguire il server di database in questa modalità, contattare l'amministratore del dominio e l'amministratore del server di database per determinare le modifiche eventualmente richieste per la configurazione di RMS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Verificare che il servizio database sia stato arrestato.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Installare qualsiasi aggiornamento del software del server di database. Quando viene richiesta una password, utilizzare la stessa password specificata durante l'installazione.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Riavviare il computer. Verificare che il servizio database sia avviato.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Verificare che gli account degli utenti abbiano indirizzi di posta elettronica validi in Active Directory.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Assicurarsi che l'utente del dominio che amministrerà RMS (ed eseguirà il provisioning dei server di certificazione principali e dei server licenze) abbia le autorizzazioni necessarie per il server di database. Se si utilizza SQL Server come server di database, è possibile aggiungere un identificatore di accesso per l'utente che sta usando lo snap-in <strong>SQL Server Enterprise Manager</strong>. Nello snap-in, espandere il server e il gruppo dei server, quindi espandere la voce <strong>Protezione</strong>. Fare clic sulla voce <strong>Accessi</strong>, aggiungere un nuovo accesso per l'account di dominio dell'utente, fare clic sulla scheda <strong>Ruoli del server</strong>, quindi selezionare la casella di controllo <strong>Amministratori del server</strong>.</p></td>
<td style="border:1px solid black;"><p>Importante: Tutti gli utenti che utilizzano RMS per acquisire licenze e pubblicare contenuti devono avere un indirizzo di posta elettronica configurato nel loro account nello snap-in Utenti e gruppi di Active Directory di MMC, nella scheda <strong>Generale</strong> delle <strong>Proprietà</strong> dell'utente.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Connessione a Internet</p>
<p>(facoltativo)</p></td>
<td style="border:1px solid black;"><p>Verificare che il browser e il server (inclusa qualsiasi configurazione di server proxy necessaria), TCP/IP e LMHOSTS/HOSTS siano configurati correttamente per accedere a Internet. Per verificarlo, accedere all'indirizzo http://uddi.microsoft.com. Se è possibile aprire questa pagina, RMS può connettersi ai Servizi di Enrollment Microsoft.</p></td>
<td style="border:1px solid black;"><p>Connettersi al sito http://uddi.microsoft.com per verificare l'accesso a Internet.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Aggiornamenti del software</p></td>
<td style="border:1px solid black;"><p>Scaricare e installare i più recenti aggiornamenti del software installato sul computer (inclusi gli ultimi aggiornamenti di Windows da www.microsoft.com).</p></td>
<td style="border:1px solid black;"><p>Scaricare e installare sempre i più recenti aggiornamento dei servizi.</p></td>
</tr>  
</tbody>  
</table>
  
Dopo aver seguito per intero la procedura precedente, è possibile eseguire la configurazione iniziale (inclusa l'installazione del software richiesto come prerequisito) sui computer che eseguiranno RMS.
