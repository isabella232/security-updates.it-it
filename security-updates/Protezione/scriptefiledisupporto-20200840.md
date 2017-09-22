---
TOCTitle: Script e file di supporto
Title: Script e file di supporto
ms:assetid: 'a03d9672-e537-477b-8ec1-d05cda6ea378'
ms:contentKeyID: 20200840
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Dd536241(v=TechNet.10)'
---

Protezione delle reti LAN senza fili con PEAP e password
========================================================

### Appendice D: Script e file di supporto

Aggiornato: 2 aprile 2004

##### In questa pagina

[](#edaa)[Introduzione](#edaa)
[](#ecaa)[Elenco dei file forniti con la soluzione](#ecaa)
[](#ebaa)[Struttura degli script](#ebaa)

### Introduzione

Questa appendice contiene una breve descrizione degli script e degli altri file di supporto forniti con la soluzione. Gli script funzionano e sono stati testati con la soluzione, ma non sono stati sottoposti a un processo completo di controllo della qualità. Scopo di questi script è illustrare le tecniche suggerite e fungere da base per la realizzazione di script di amministrazione personalizzati. Prima di utilizzarli nell'ambiente di produzione è consigliabile sottoporli a test completi.

#### Dichiarazione di non responsabilità

Gli script di esempio non sono supportati da nessun programma o servizio di supporto standard di Microsoft®. Gli script di esempio vengono forniti COSÌ COME SONO, senza garanzia di alcun tipo. Microsoft non riconosce alcuna garanzia implicita, comprese, tra le altre, la garanzia di commerciabilità e/o idoneità per un fine particolare. L'utente utilizza gli script di esempio e la documentazione a suo rischio. Microsoft o i suoi autori o chiunque sia coinvolto nella creazione, produzione o distribuzione degli script non saranno, in alcun caso, responsabili per danni di qualsiasi tipo, inclusi, tra gli altri, la perdita di profitti, la perdita di informazioni o altre perdite pecuniarie, derivanti dall'uso o dall'impossibilità di utilizzare gli script di esempio o la documentazione, anche se Microsoft sia stata informata della possibilità del verificarsi di tali danni.

[](#mainsection)[Inizio pagina](#mainsection)

### Elenco dei file forniti con la soluzione

Nella tabella seguente sono elencati tutti i file forniti con la soluzione. Questi file vengono installati dal file MSSWLANTools.msi di Windows® Installer.

**Tabella D.1: Elenco dei file forniti con la soluzione**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome file</p></th>
<th><p>Descrizione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p><strong>File CMD principali</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>MSSSetup.cmd</p>
<p>MSSTools.cmd</p></td>
<td style="border:1px solid black;"><p>Sono i file batch che forniscono l'interfaccia per i file Microsoft Windows Scripting Host (WSH) e semplificano la sintassi. Consentono di eseguire vari processi specificando il nome del processo come unico parametro della riga di comando. La sintassi è la seguente:</p>
<p><strong>msssetup</strong><em>NomeProcesso</em> [/param:<em>valore</em>]</p>  
<p><strong>msstools</strong> <em>NomeProcesso</em> [/param:<em>valore</em>]</p>
<p>dove <em>NomeProcesso</em> è il nome dell'operazione. Se si esegue questo script senza specificare un nome di processo, verranno elencati tutti i processi disponibili, insieme a una breve descrizione della funzione di ognuno.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p><strong>File XML WSH</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>msssetup.wsf</p>
<p>msstools.wsf</p></td>
<td style="border:1px solid black;"><p>Sono file XML WSH, che specificano i singoli processi disponibili. I processi definiti nei file WSF richiamano procedure definite nei file VBS. La sintassi è la seguente:</p>
<p><strong>Cscript //job:</strong><em>NomeProcesso</em> msstools.wsf [/param:<em>valore</em>]</p>
<p>Se si esegue questo script senza specificare un nome di processo, viene elencato il contenuto del file WSF insieme a una breve descrizione della funzione di ogni processo.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p><strong>File VBScript</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ias_setup.vbs</p></td>
<td style="border:1px solid black;"><p>Routine utilizzate durante l'installazione del Servizio autenticazione Internet (IAS).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ias_tools.vbs</p></td>
<td style="border:1px solid black;"><p>Routine utilizzate durante l'esercizio e il monitoraggio di IAS.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Gen_setup.vbs</p></td>
<td style="border:1px solid black;"><p>Routine non specifiche di IAS o di Servizi certificati, utilizzate durante l'implementazione.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ca_setup.vbs</p></td>
<td style="border:1px solid black;"><p>Routine utilizzate durante l'installazione dell'Autorità di certificazione (CA).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ca_monitor.vbs</p></td>
<td style="border:1px solid black;"><p>Routine utilizzate dalle funzioni di monitoraggio della CA.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>constants.vbs</p></td>
<td style="border:1px solid black;"><p>Costanti utilizzate dagli altri file VBS.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>helper.vbs</p></td>
<td style="border:1px solid black;"><p>Routine generiche utilizzate dagli altri file VBS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Pkiparams.vbs</p></td>
<td style="border:1px solid black;"><p>Costanti utilizzate per definire molti dei parametri di installazione della CA.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p><strong>File vari</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>InstCAPICOM.cmd</p></td>
<td style="border:1px solid black;"><p>File CMD che semplifica l'installazione di CAPICOM.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CreateShortCut.cmd</p></td>
<td style="border:1px solid black;"><p>File CMD che richiama una routine dal file VBS per creare un collegamento sul desktop dell'utente. Il collegamento consente di avviare CMD.EXE con impostata la cartella di installazione degli script come directory corrente.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ComputerCerts.msc</p></td>
<td style="border:1px solid black;"><p>Console di gestione predefinita per la visualizzazione dei certificati nell'archivio del computer.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>AddRADIUSClient.exe</p></td>
<td style="border:1px solid black;"><p>Utilità che consente di aggiungere client RADIUS a IAS dalla riga di comando. (<strong>Nota:</strong> per poter utilizzare questo strumento deve essere installato .NET Framework.)</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Interop.SDOIASLib.dll</p></td>
<td style="border:1px solid black;"><p>Libreria di supporto richiesta da AddRADIUSClient.exe.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Source</p></td>
<td style="border:1px solid black;"><p>Cartella contenente il codice sorgente per lo strumento AddRADIUSClient.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p><strong>File criteri di gruppo</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>MSSWLANGPOs</p></td>
<td style="border:1px solid black;"><p>Questa cartella contiene il file di definizione XML e i file di dati per i due oggetti Criteri di gruppo predefiniti forniti con questa soluzione.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p><strong>Documenti</strong></p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Securing Wireless LANs.rtf</p></td>
<td style="border:1px solid black;"><p>File leggimi contenente lo stesso testo di questa appendice.</p></td>
</tr>  
</tbody>  
</table>
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Struttura degli script
  
Per comprendere il funzionamento e le interazioni dei file Microsoft Visual Basic® Scripting Edition (VBScript) sono necessarie alcune spiegazioni. A differenza di molti esempi VBScript, i file script forniti con la soluzione contengono più funzioni, spesso indipendenti. Per fornire l'accesso a queste diverse funzioni, negli script viene utilizzata la funzionalità "job" (processo) di WSH. Grazie ad essa, diverse funzioni di programma indipendenti possono essere contenute in uno stesso file e da questo richiamate specificando un nome di processo come parametro dello script.
  
Vi sono due file WSF (Windows Script), che contengono l'interfaccia utente per tutte le diverse operazioni di script. I file WSF richiamano una serie di file VBS, i quali contengono il codice che in realtà svolge il lavoro di un determinato processo.
  
È possibile richiamare il processo utilizzando la seguente sintassi:
  
**cscript //job:***NomeProcessoWScriptFile*.wsf
  
dove *NomeProcesso* è il nome dell'operazione e *WScriptFile* è il nome del file di interfaccia XML per lo script. Di seguito è riportato un estratto di uno dei file WSF, in cui è definito il processo ConfigureCA:
  
<codesnippet language displaylanguage containsmarkup="false"> &lt;?xml version="1.0" encoding="utf-8" ?&gt; &lt;package xmlns="Windows Script Host"&gt; &lt;job id="ConfigureCA"&gt; &lt;description&gt;Configures the CA registry parameters&lt;/description&gt; &lt;script language="VBScript" src="constants.vbs" /&gt; &lt;script language="VBScript" src="pkiparams.vbs" /&gt; &lt;script language="VBScript" src="helper.vbs" /&gt; &lt;script language="VBScript" src="ca\_setup.vbs" /&gt; &lt;script language="VBScript"&gt; &lt;!\[CDATA\[ Initialize True, True ConfigureCA CloseDown \]\]&gt; &lt;/script&gt;   
```  
In questo estratto, la definizione del processo specifica che i file VBS, cioè constants.vbs, pkiparams.vbs, helper.vbs e ca\_setup.vbs, contengono funzioni, subroutine o dati richiesti da questo processo e, pertanto, devono essere caricati. La sezione finale specifica le funzioni di livello superiore che devono essere eseguite per avviare il processo. In questo caso queste funzioni sono Initialize (che imposta la registrazione), ConfigureCA (che esegue il processo di configurazione della CA) e CloseDown (che chiude il registro).
  
In ognuno dei file WSF, il primo processo elenca i nomi (ID) e le descrizioni di tutti i processi contenuti nel file. Pertanto, se il file WSF viene eseguito senza che sia specificato un processo specifico, viene eseguito questo processo predefinito e viene visualizzata una schermata con i nomi e le descrizioni di tutti i processi disponibili nel file. Nella tabella seguente sono elencati i processi disponibili in ognuno dei file WSF forniti con la soluzione.
  
**Tabella D.2: Elenco dei processi in MSSSetup.wsf**

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="50%" />  
<col width="50%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th><p>Nome processo</p></th>  
<th><p>Descrizione</p></th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>ListJobs</p></td>
<td style="border:1px solid black;"><p>Elenca tutti i processi presenti nel file WSF.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ConfigureCA</p></td>
<td style="border:1px solid black;"><p>Configura i parametri del Registro di sistema per la CA.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ConfigureTemplates</p></td>
<td style="border:1px solid black;"><p>Configura i modelli dei certificati della CA.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CheckCAEnvironment</p></td>
<td style="border:1px solid black;"><p>Controlla l'ambiente prima dell'installazione della CA.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>InstallCA</p></td>
<td style="border:1px solid black;"><p>Installa Servizi certificati.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CreateShortcut</p></td>
<td style="border:1px solid black;"><p>Crea il collegamento a <strong>MSS WLAN Tools</strong> sul desktop.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ImportSecurityGPO</p></td>
<td style="border:1px solid black;"><p>Importa nel dominio l'oggetto Criteri di gruppo con le impostazioni per la protezione dei server.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ImportAutoEnrollGPO</p></td>
<td style="border:1px solid black;"><p>Importa nel dominio l'oggetto Criteri di gruppo con le impostazioni per la registrazione automatica dei certificati.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ImportWLANClientGPO*</p></td>
<td style="border:1px solid black;"><p>Importa l'oggetto Criteri di gruppo con le impostazioni per la rete WLAN</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CheckDomainNativeMode</p></td>
<td style="border:1px solid black;"><p>Controlla che il dominio sia in modalità nativa.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>VerifyCAInstall</p></td>
<td style="border:1px solid black;"><p>Verifica che la CA sia stata installata in modo corretto.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>VerifyCAConfig</p></td>
<td style="border:1px solid black;"><p>Verifica che la CA sia stata configurata in modo corretto.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CheckIASEnvironment</p></td>
<td style="border:1px solid black;"><p>Controlla l'ambiente prima dell'installazione di IAS.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>InstallIAS</p></td>
<td style="border:1px solid black;"><p>Installa il Servizio autenticazione Internet sul server.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CreateWLANGroups</p></td>
<td style="border:1px solid black;"><p>Crea i gruppi di protezione in Active Directory®.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>AddWLANGroupMembers</p></td>
<td style="border:1px solid black;"><p>Popola i gruppi di protezione con i membri corretti.</p></td>
</tr>  
</tbody>  
</table>
  
**Nota:** i processi contrassegnati con un asterisco (\*) non vengono utilizzati in questa soluzione.
  
**Tabella D.3: Elenco dei processi in MSSTools.wsf**

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="50%" />  
<col width="50%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th><p>Nome processo</p></th>  
<th><p>Descrizione</p></th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>ListJobs</p></td>
<td style="border:1px solid black;"><p>Elenca tutti i processi presenti nel file WSF.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>AddRADIUSClient</p></td>
<td style="border:1px solid black;"><p>Procedura interattiva per aggiungere un client RADIUS a IAS (parametri: [/path:<em>NomeFileOutput</em>]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>AddSecRADIUSClients</p></td>
<td style="border:1px solid black;"><p>Procedura interattiva per aggiungere un client RADIUS a IAS (parametri: [/path:<em>NomeFileInput</em>]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>GenRADIUSPwd</p></td>
<td style="border:1px solid black;"><p>Genera voce e password per il client RADIUS (parametri: /client:<em>NomeClient</em> /ip:<em>IndirizzoIPClient</em> [/path:<em>FileOutput</em>]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ExportIASSettings</p></td>
<td style="border:1px solid black;"><p>Esporta su file la configurazione del server IAS (parametri: [/path:<em>CartellaDestinazioneFileImpostazioni</em>]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ImportIASSettings</p></td>
<td style="border:1px solid black;"><p>Importa dai file la configurazione del server IAS (parametri: [/path:<em>CartellaFileDaImportare</em>]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ExportIASClients</p></td>
<td style="border:1px solid black;"><p>Esporta su file i client RADIUS (parametri: [/path:<em>CartellaDestinazioneFileClient</em>]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ImportIASClients</p></td>
<td style="border:1px solid black;"><p>Importa dal file i client RADIUS (parametri: [/path:<em>CartellaFileClientDaImportare</em>]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>BackupIAS</p></td>
<td style="border:1px solid black;"><p>Esegue il backup su file di tutte le impostazioni di IAS (parametri: [/path:<em>CartellaDestinazioneFileBackup</em>]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>RestoreIAS</p></td>
<td style="border:1px solid black;"><p>Ripristina da file tutte le impostazioni di IAS (parametri: [/path:<em>CartellaFileDaRipristinare</em>]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>CheckIAS</p></td>
<td style="border:1px solid black;"><p>Controlla che il server IAS risponda (parametri: [/verbose]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>CheckCA</p></td>
<td style="border:1px solid black;"><p>Controlla che il servizio CA risponda e che l'elenco di revoca dei certificati (CRL) sia valido (parametri: [/verbose]).</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>EnableIASLockout*</p></td>
<td style="border:1px solid black;"><p>Attiva il blocco degli account per IAS (parametri: [/maxdenials:<em>10</em>] [/lockouttime:<em>2880</em> (secs)]).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>DisableIASLockout*</p></td>
<td style="border:1px solid black;"><p>Disattiva il blocco degli account per IAS.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>ShowLockedOutAccounts*</p></td>
<td style="border:1px solid black;"><p>Mostra gli account bloccati (e gli account con richieste di autorizzazione respinte).</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ResetLockedOutAccount*</p></td>
<td style="border:1px solid black;"><p>Reimposta un account bloccato (parametri: /account:<em>NomeDominio:NomeAccount</em>).</p></td>
</tr>  
</tbody>  
</table>
  
**Nota:** i processi contrassegnati con un asterisco (\*) non vengono utilizzati in questa soluzione.
  
#### Output dei processi
  
La maggior parte degli script registrano informazioni sullo stato in una finestra di console e, in molti casi, anche in un file registro. Queste informazioni possono includere informazioni sugli errori, se si sono verificati problemi durante l'esecuzione. Costituiscono un'eccezione gli script di monitoraggio, perché vengono eseguiti come processi pianificati non interattivi e non inviano output a una finestra di console.
  
Per visualizzare l'output degli script viene utilizzata una semplice finestra a scorrimento. Al termine di ogni script viene chiesto di scegliere se lasciare aperta la finestra (per riferimento) o se chiuderla.
  
Per la maggior parte delle procedure di installazione, l'output viene registrato anche in un file denominato %SystemRoot%\\debug\\MSSWLAN-Setup.log. La maggior parte delle normali attività operative non viene registrata. Vengono registrate, comunque, le attività che possono avere conseguenze importanti sulla protezione o sul funzionamento, come, ad esempio, l'importazione della configurazione di IAS. Non vengono registrate neanche le attività che possono comportare la scrittura di informazioni riservate nel registro, come l'aggiunta di client RADIUS e la creazione dei rispettivi segreti.
  
#### Esecuzione dei processi
  
Gli script possono essere eseguiti direttamente, tuttavia sono disponibili due file batch (cmd) della shell comandi che semplificano la sintassi.
  
La sintassi per l'esecuzione diretta dei file WSF è la seguente:
  
**Cscript //job:***NomeProcesso* MssSetup.wsf
  
Al suo posto è possibile utilizzare i file CMD con la seguente sintassi, più semplice:
  
**MssSetup***NomeProcesso*
  
Se si esegue il file CMD senza specificare un processo, viene eseguito il primo processo (ListJobs) del file WSF, che elenca l'ID e la descrizione di ogni processo contenuto nel file WSF.
  
Alcuni processi accettano anche ulteriori parametri. La sintassi per l'esecuzione di tali processi e le informazioni sui parametri aggiuntivi vengono trattate nei capitoli di pertinenza di questa soluzione. La sintassi generica per specificare ulteriori parametri è la seguente:
  
**MssSetup***NomeProcesso* /NomeParam:*ValoreParam*
  
*NomeParam* è il nome del parametro (ad esempio "path" o "client") e *ValoreParam* è l'impostazione per tale parametro (ad esempio "C:\\MioFile.txt" o "MioComputer"). I valori dei parametri che contengono spazi incorporati devono essere racchiusi tra virgolette (").
  
**Scarica la soluzione completa**
  
[Protezione delle reti LAN senza fili con PEAP e password](http://go.microsoft.com/fwlink/?linkid=23481)
  
[](#mainsection)[Inizio pagina](#mainsection)
