---
TOCTitle: 'Capitolo 9: Ruolo del server Web'
Title: 'Capitolo 9: Ruolo del server Web'
ms:assetid: 'ae41b3f3-b46f-4818-ae75-3aaf23075b56'
ms:contentKeyID: 20213209
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc163131(v=TechNet.10)'
---

Guida per la protezione di Windows Server 2003
==============================================

### Capitolo 9: Ruolo del server Web

##### In questa pagina

[](#eiaa)[Panoramica](#eiaa)
[](#ehaa)[Accesso anonimo e Impostazioni SSLF](#ehaa)
[](#egaa)[Impostazioni del Criterio Controllo](#egaa)
[](#efaa)[Assegnazione dei diritti utente](#efaa)
[](#eeaa)[Opzioni di protezione](#eeaa)
[](#edaa)[Impostazioni del Registro eventi](#edaa)
[](#ecaa)[Impostazioni di protezione aggiuntive](#ecaa)
[](#ebaa)[Creazione del criterio utilizzando SCW](#ebaa)
[](#eaaa)[Riepilogo](#eaaa)

### Panoramica

Questo capitolo fornisce indicazioni per migliorare la sicurezza dei server Web che eseguono Microsoft Windows* * Server* * 2003 con SP1 nell'ambiente in uso. Per ottenere una protezione completa delle applicazioni e dei server Web all'interno della Intranet dell'organizzazione, Microsoft consiglia di proteggere ogni server con Microsoft Internet* *Information* *Services (IIS) e ogni applicazione e sito Web in esecuzione su questi server da computer client in grado di connettersi a essi. È inoltre necessario proteggere tali applicazioni e siti Web dalle applicazioni e dai siti Web in esecuzione su altri server IIS all'interno della Intranet dell'organizzazione.

Per fornire protezione da utenti malintenzionati e pirati informatici, la configurazione predefinita per i membri della famiglia Windows Server 2003 non installa IIS. Durante l'installazione, IIS è configurato in una in modalità altamente protetta, definita "bloccata". Per esempio, nello stato predefinito, IIS fornirà solo contenuti statici. Funzionalità quali le pagine ASP (Active Server Pages), ASP.NET, SSI (Server Side Includes), la pubblicazione WebDAV (Web Distributed Authoring and Versioning) e le estensioni del server Microsoft FrontPage non funzionano finché non vengono attivate da un amministratore. Queste funzioni e servizi possono essere attivati attraverso il nodo Estensioni del servizio Web di Gestione Internet Information Services (Gestione IIS). Gestione IIS è dotato di un'interfaccia grafica progettata per facilitare l'amministrazione di IIS. Comprende risorse per la gestione di file e directory, nonché la configurazione di pool di applicazioni, oltre che funzionalità che vanno a vantaggio della protezione, delle prestazioni e dell'affidabilità.

Per migliorare la protezione dei server Web IIS che ospitano contenuto HTML all'interno della Intranet dell'organizzazione, è necessario prendere in considerazione l'implementazione delle impostazioni descritte nelle seguenti sezioni del presente capitolo. Per proteggere i server, è inoltre necessario implementare procedure di monitoraggio della protezione, rilevazione e risposta, per poter rilevare nuovi pericoli.

La maggior parte delle impostazioni in questo capitolo sono configurate e applicate tramite il criterio di gruppo. Un GPO incrementale che integra i criteri MSBP è collegato alle unità organizzative appropriate e fornisce protezione aggiuntiva per i server Web. Per migliorare l'utilizzabilità del presente capitolo, vengono trattate soltanto le impostazioni dei criteri che differiscono da quelle dei criteri MSBP.

Dove possibile, queste impostazioni sono raccolte in un modello dei Criteri di Gruppo incrementale, che verrà applicato all'unità organizzativa dei Server Web. Alcune delle impostazioni in questo capitolo non possono essere applicate tramite il criterio di gruppo. Vengono fornite informazioni dettagliate su come configurare manualmente queste impostazioni.

La tabella seguente mostra i nomi dei modelli di protezione dei server Web per i tre ambienti definiti in questa guida. Tali modelli di protezione di server Web forniscono le impostazioni dei criteri per il modello di Server Web incrementale. È possibile utilizzare questo modello per creare un nuovo GPO, collegato all'OU dei Server Web nell'ambiente appropriato. Il capitolo 2, "Meccanismi di protezione avanzata di Windows* *Server* *2003", fornisce istruzioni dettagliate per creare OU e Criteri di gruppo e importare poi il modello di protezione adeguato in ogni GPO.

**Tabella 9.1 Modelli di protezione dei server IIS**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Legacy Client</p></th>
<th><p>Enterprise Client</p></th>
<th><p>Specialized Security – Limited Functionality</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>LC-Web Server.inf</p></td>
<td style="border:1px solid black;"><p>EC-Web Server.inf</p></td>
<td style="border:1px solid black;"><p>SSLF-Web Server.inf</p></td>
</tr>
</tbody>
</table>
  
Per informazioni riguardanti tutte le impostazioni predefinite, consultare la guida correlata [*Pericoli e contromisure: impostazioni di protezione in Windows Server 2003 e Windows XP*](http://technet.microsoft.com/it-it/library/dd162275), disponibile all'indirizzo http://www.microsoft.com/italy/technet/security/topics/serversecurity/tcg/tcgch00.mspx.
  
Questa guida illustra come proteggere IIS, avendo installato e attivato le funzionalità minime. Se si intende utilizzare le funzionalità aggiuntive IIS, potrebbe essere necessario adeguare alcune delle impostazioni di protezione. Se si installano servizi aggiuntivi quali SMTP, FTP, o NNTP, sarà necessario adeguare i modelli e i criteri forniti.
  
L'articolo in linea "[IIS and Built-in Accounts (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/3648346f-e4f5-474b-86c7-5a86e85fa1ff.mspx)" (in inglese) all'indirizzo www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/  
3648346f-e4f5-474b-86c7-5a86e85fa1ff.mspx descrive gli account utilizzati dalle varie funzionalità di IIS e i privilegi necessari per ciascuna di queste. Per implementare impostazioni più sicure sui server Web che ospitano applicazioni complesse, può risultare utile esaminare la documentazione IIS 6.0 completa all'indirizzo http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/  
Library/IIS/848968f3-baa0-46f9-b1e6-ef81dd09b015.mspx (in inglese).
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Accesso anonimo e Impostazioni SSLF
  
Quattro dei diritti utente, esplicitamente definiti nello scenario SSLF all'interno dei criteri MSBP, sono finalizzati a evitare l'accesso anonimo ai siti Web IIS. Tuttavia, qualora fosse necessario consentire l'accesso anonimo a un ambiente SSLF, si dovranno apportare importanti cambiamenti alla struttura dell'unità organizzativa e ai GPO, descritti nei capitoli 2, 3 e 4 della presente guida. Sarà necessario creare una nuova OU che non faccia parte della gerarchia di livello inferiore rispetto all'unità organizzativa dei server membro. Questa OU potrebbe essere direttamente collegata alla directory principale di dominio, o potrebbe essere una OU figlio di un' altra struttura gerarchica di OU. In ogni caso, non si devono assegnare diritti utente in un GPO che compromettano i server IIS collocati in questa nuova OU. È possibile spostare i server IIS nella nuova OU, creare un nuovo GPO, applicarvi le impostazioni dei criteri MSBP e riconfigurare poi le assegnazioni dei diritti utente, in modo che possano essere controllate da criteri locali anziché da un GPO basato sul dominio. In altre parole, in questo nuovo GPO è necessario configurare le seguenti impostazioni dei diritti utente su **Non definito**.
  
-   Accesso al computer dalla rete
  
-   Consenti accesso locale
  
-   Ignora controllo visite
  
-   Accesso come processo batch
  
Le funzioni IIS da abilitare determineranno se sarà necessario riconfigurare anche le altre impostazioni per l'assegnazione dei diritti utente su **Non definito.**
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Impostazioni del Criterio Controllo
  
Le impostazioni del Criterio di controllo per i server IIS nei tre ambienti definiti in questa guida sono configurate tramite i criteri di base dei server membro (MSBP). Per ulteriori informazioni sul criterio MSBP, consultare il Capitolo 4, "Criterio di base per un server membro". Le impostazioni del criterio MSBP assicurano che tutte le informazioni di controllo della protezione pertinenti siano registrate su tutti i server IIS.
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Assegnazione dei diritti utente
  
Le impostazioni per l'assegnazione dei diritti utente per i server IIS nei tre ambienti qui definiti sono configurate tramite i criteri MSBP. Per ulteriori informazioni sul criterio MSBP, consultare il Capitolo 4, "Criterio di base per un server membro". Le impostazioni del criterio MSBP assicurano che tutte le informazioni di controllo della protezione pertinenti siano registrate su tutti i server IIS.
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Opzioni di protezione
  
Le impostazioni delle opzioni di protezione per i server IIS nei tre ambienti definiti in questa guida sono configurate tramite i criteri MSBP. Per ulteriori informazioni sui criteri MSBP, consultare il Capitolo 4, "Criterio di base per un server membro". Le impostazioni del criterio MSBP assicurano che tutte le opzioni di protezione rilevanti siano configurate in modo uniforme su tutti i server IIS.
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Impostazioni del Registro eventi
  
Le impostazioni del registro eventi per i server IIS nei tre ambienti definiti in questa guida sono configurate tramite i criteri MSBP. Per ulteriori informazioni sui criteri MSBP, consultare il capitolo 4, "Criterio di base per un server membro." Le impostazioni dei criteri MSBP assicurano che adeguate impostazioni del registro eventi siano uniformemente configurate su tutti i server IIS di un'organizzazione.
  
[](#mainsection)[Inizio pagina](#mainsection)
  
### Impostazioni di protezione aggiuntive
  
Quando IIS è installato su un computer che esegue Windows* *Server* *2003 con SP1, l' impostazione predefinita consente solo la trasmissione di contenuti Web statici. Quando le applicazioni e i siti Web comprendono contenuti dinamici o richiedono uno o più componenti aggiuntivi di IIS, ogni caratteristica aggiuntiva deve essere attivata singolarmente. Tuttavia, è necessario prestare attenzione alla riduzione della superficie di attacco di ogni server IIS nell'ambiente in uso. Se i siti Web dell'organizzazione includono contenuti statici e non richiedono altri componenti di IIS, la configurazione predefinita di IIS è sufficiente per ridurre al minimo la superficie di attacco dei server IIS.
  
Le impostazioni di protezione applicate attraverso i criteri MSBP forniscono una protezione notevolmente maggiore per i server IIS. Tuttavia, esistono alcune impostazioni aggiuntive che è necessario considerare. Le impostazioni nelle seguenti sezioni non possono essere implementate attraverso i Criteri di gruppo e devono essere quindi eseguite manualmente su tutti i server IIS.
  
#### Installazione dei soli componenti IIS necessari
  
IIS 6.0 contiene altri componenti e servizi oltre al servizio Pubblicazione sul Web, come i servizi richiesti per garantire i supporti FTP, NNTP e SMTP. I componenti e servizi di IIS vengono installati e attivati dal server delle applicazioni dell'Aggiunta guidata componenti di Windows che si può lanciare attraverso Installazione applicazioni nel Pannello di controllo. Dopo l'installazione di IIS, è necessario attivare tutti i componenti e i servizi di IIS richiesti dalle applicazioni e dai siti Web.
  
**Per installare Internet Information Services (IIS) 6.0**
  
1.  Nel Pannello di controllo, fare doppio clic su **Installazione applicazioni.**
  
2.  Fare clic sul pulsante **Installazione componenti di Windows** per avviare l'Aggiunta guidata componenti di Windows.
  
3.  Nell'elenco **Componenti**, fare clic su **Server applicazioni**, quindi su **Dettagli**.
  
4.  Nella finestra di dialogo **Server applicazioni**, in **Sottocomponenti di Server applicazioni**, fare clic su **Internet Information Services (IIS)**, quindi su **Dettagli**.
  
5.  Nella finestra di dialogo **Internet Information Services (IIS** ), all'interno dell'elenco **Sottocomponenti di Internet Information Services (IIS**), eseguire una delle seguenti operazioni:
  
    -   Per aggiungere componenti opzionali, selezionare la casella di controllo corrispondente al componente che si desidera installare.
  
    -   Per rimuovere componenti opzionali, deselezionare la casella di controllo corrispondente al componente che si desidera rimuovere.
  
6.  Scegliere **OK** fino a tornare all'Aggiunta guidata componenti di Windows.
  
7.  Scegliere **Avanti**, quindi **Fine**.
  
Si consiglia di attivare solo i componenti e i servizi essenziali di IIS che vengono richiesti dalle applicazioni e dai siti Web. Se si attivano componenti e servizi non necessari, la superficie di attacco di un server IIS aumenta. Le illustrazioni e le tabelle seguenti mostrano la posizione e le impostazioni suggerite per i componenti di IIS.
  
La seguente figura mostra i sottocomponenti nella finestra di dialogo **Server applicazioni**:
  
[![](images/Cc163131.sgfg0901(it-it,TechNet.10).gif)](https://technet.microsoft.com/it-it/cc163131.sgfg0901_big(it-it,technet.10).gif)
  
**Figura 9.1 Finestra di dialogo Server applicazioni con elenco dei sottocomponenti**
  
Nella seguente tabella sono descritti i sottocomponenti di Server applicazioni e vengono fornite indicazioni sui casi in cui è consigliabile attivarli.
  
**Tabella 9.2 Impostazioni consigliate dei sottocomponenti di Server applicazioni**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome del componente nell'interfaccia utente</p></th>
<th><p>Impostazione</p></th>
<th><p>Logica dell'impostazione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Console di Server applicazioni</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce uno snap-in Microsoft Management Console (MMC) utilizzabile per amministrare tutti i componenti del Server per le applicazioni Web. In un server IIS dedicato è possibile utilizzare Gestione server IIS, pertanto il componente non è richiesto.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>ASP.NET</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce supporto per le applicazioni ASP.NET. Va abilitato quando in un server IIS sono in esecuzione applicazioni ASP.NET.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Enable network COM+ access</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>Consente a un server IIS server di ospitare componenti COM+ per applicazioni distribuite. È richiesto, tra l'altro, per l'estensione server BITS, FTP, Servizio Web e Gestione IIS.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Abilita accesso DTC alla rete</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Consente a un server IIS di ospitare applicazioni che partecipano alle transazioni di rete tramite Distributed Transaction Coordinator (DTC). Il componente deve essere disabilitato, a meno che le applicazioni in esecuzione nel server IIS lo richiedano.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Internet Information Services (IIS)</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>Fornisce servizi Web e FTP di base. Il componente è necessario per i server IIS dedicati.</p>
<p><strong>Nota</strong>: se questo componente è disabilitato, lo sono anche tutti i relativi sottocomponenti.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Accodamento messaggi</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Microsoft Accodamento messaggi (MSMQ) fornisce un livello middleware per il routing, l'archiviazione e l'inoltro di messaggi per le applicazioni Web dell'organizzazione.</p></td>
</tr>
</tbody>
</table>
  
La seguente figura mostra i sottocomponenti all'interno della finestra di dialogo **Internet Information Services (IIS)**:
  
[![](images/Cc163131.sgfg0902(it-it,TechNet.10).gif)](https://technet.microsoft.com/it-it/cc163131.sgfg0902_big(it-it,technet.10).gif)
  
**Figura 9.2 Finestra di dialogo IIS con elenco dei sottocomponenti**
  
Nella seguente tabella sono descritti i sottocomponenti di IIS e vengono fornite indicazioni sui casi in cui è consigliabile attivarli.
  
**Tabella 9.3 Impostazioni consigliate per i sottocomponenti di IIS**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome del componente nell'interfaccia utente</p></th>
<th><p>Impostazione</p></th>
<th><p>Logica dell'impostazione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Estensione server Servizio trasferimento intelligente in background (BITS)</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>L'estensione server BITS consente al servizio BITS nei client di caricare dei file su questo server in background. Se si ha un'applicazione nei client che utilizza BITS per caricare i file su questo server, attivare e configurare l'estensione server BITS; in caso contrario, lasciarla disattivata. Windows Update, Microsoft Update, SUS, WSUS e Aggiornamenti automatici non richiedono l'esecuzione di questo componente. Richiedono invece il componente del cliente BITS, che non fa parte di IIS.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>File comuni</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>IIS richiede questi file, che pertanto devono sempre essere abilitati nei server IIS.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Servizio FTP (File Transfer Protocol)</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Consente ai server IIS di fornire servizi FTP. Il componente non è necessario per i server IIS dedicati.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Estensioni del server di FrontPage 2002</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce il supporto FrontPage per l'amministrazione e la pubblicazione di siti Web. Può essere disabilitato nei server IIS dedicati quando le estensioni FrontPage non vengono utilizzate in alcun sito Web.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Gestione di Internet Information Services</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>Interfaccia amministrativa per IIS.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Stampa Internet</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Consente di gestire le stampanti sul Web e di condividerle su HTTP. Non è necessario per i server IIS dedicati.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Servizio NNTP</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Consente di distribuire, interrogare, recuperare e inserire articoli di Usenet su Internet. Non è necessario per i server IIS dedicati.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Servizio SMTP</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Supporta il trasferimento di posta elettronica. Non è necessario per i server IIS dedicati.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Servizio Web</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>Fornisce servizi Web e contenuto statico e dinamico ai client. Il componente è necessario per i server IIS dedicati.</p></td>
</tr>
</tbody>
</table>
  
La seguente figura mostra i sottocomponenti nella finestra di dialogo **Accodamento messaggi**:
  
[![](images/Cc163131.sgfg0903(it-it,TechNet.10).gif)](https://technet.microsoft.com/it-it/cc163131.sgfg0903_big(it-it,technet.10).gif)
  
**Figura 9.3 Finestra di dialogo Accodamento messaggi con elenco dei sottocomponenti**
  
Nella seguente tabella sono descritti i sottocomponenti di Accodamento messaggi e vengono fornite indicazioni sui casi in cui è consigliabile attivarli.
  
**Tabella 9.4 Impostazioni consigliate per i sottocomponenti di Accodamento messaggi**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome del componente nell'interfaccia utente</p></th>
<th><p>Opzione di installazione</p></th>
<th><p>Logica dell'impostazione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Integrazione di Active Directory</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce integrazione con il servizio directory Active<em> </em>Directory per tutti i server IIS appartenenti a un dominio. Questo componente è necessario quando per i siti Web e le applicazioni in esecuzione su server IIS è utilizzato Microsoft Accodamento messaggi (MSMQ).</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Comuni</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>È necessario quando i siti Web e le applicazioni in esecuzione sul server IIS utilizzano MSMQ.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Supporto client di livello inferiore</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce accesso ad Active<em> </em>Directory e al riconoscimento siti per i client downstream. È necessario quando i siti Web e le applicazioni di un server IIS utilizzano MSMQ.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Supporto HTTP MSMQ</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Consente di inviare e ricevere i messaggi mediante il trasporto HTTP. È necessario quando i siti Web e le applicazioni di un server IIS utilizzano MSMQ.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Supporto routing</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Offre servizi di archiviazione e inoltro, oltre a servizi di routing efficienti per MSMQ. È necessario quando i siti Web e le applicazioni in esecuzione sul server IIS utilizzano MSMQ.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Trigger</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Associa l'arrivo di messaggi in entrata a una coda con funzionalità in un componente COM o in un programma eseguibile in modalità autonoma.</p></td>
</tr>
</tbody>
</table>
  
La seguente figura mostra i sottocomponenti nella finestra di dialogo **Estensione server Servizio trasferimento intelligente in background (BITS)**:
  
[![](images/Cc163131.sgfg0904(it-it,TechNet.10).gif)](https://technet.microsoft.com/it-it/cc163131.sgfg0904_big(it-it,technet.10).gif)
  
**Figura 9.4 Estensione server BITS con elenco dei sottocomponenti**
  
Nella seguente tabella sono descritti i sottocomponenti dell'Estensione server BITS e vengono fornite indicazioni sui casi in cui è consigliabile attivarli.
  
**Tabella 9.5 Impostazioni consigliate per i sottocomponenti dell'Estensione server BITS**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome del componente nell'interfaccia utente</p></th>
<th><p>Opzione di installazione</p></th>
<th><p>Logica dell'impostazione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Snap-in della console di gestione BITS</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Installa uno snap-in MMC per l'amministrazione di BITS. Deve essere abilitato se è abilitata l'estensione server BITS per ISAPI (Internet Server Application Programming Interface).</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>ISAPI di Estensione server BITS</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Installa l'ISAPI BITS, che consente a un server IIS di trasferire dati utilizzando BITS. L'estensione server BITS consente al servizio BITS nei client di caricare file su questo server in background. Se si ha un'applicazione nei client che utilizza BITS per caricare i file su questo server, attivare e configurare l'estensione server BITS; in caso contrario, lasciarla disattivata. Windows Update, Microsoft Update, SUS, WSUS e Aggiornamenti automatici non richiedono l'esecuzione di questo componente. Richiedono invece il componente del cliente BITS, che non fa parte di IIS.</p></td>
</tr>
</tbody>
</table>
  
La seguente figura mostra i sottocomponenti nella finestra di dialogo **Servizio Web**:
  
[![](images/Cc163131.SGFG0905(it-it,TechNet.10).gif)](https://technet.microsoft.com/it-it/cc163131.sgfg0905_big(it-it,technet.10).gif)
  
**Figura 9.5 Finestra di dialogo Servizio Web con elenco dei sottocomponenti**
  
Nella tabella 5 sono descritti i sottocomponenti di Servizio Web e vengono fornite indicazioni sui casi in cui è consigliabile attivarli.
  
**Tabella 9.6 Impostazioni consigliate per i sottocomponenti di Servizio Web**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Nome del componente nell'interfaccia utente</p></th>
<th><p>Opzione di installazione</p></th>
<th><p>Logica dell'impostazione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Active Server Pages</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce il supporto per ASP. Disabilitare questo componente quando nessun sito Web o applicazione nei server IIS utilizza ASP oppure utilizzando le estensioni del servizio Web. Per ulteriori informazioni, consultare il paragrafo “Abilitazione delle sole estensioni essenziali del servizio Web&quot; all'interno di questo capitolo.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Internet Data Connector</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce il supporto per il contenuto dinamico reso disponibile mediante file con estensione .idc. Disabilitare questo componente quando nessun sito Web o applicazione in esecuzione nei server IIS include file con estensione .idc oppure utilizzando le estensioni del servizio Web. Per ulteriori informazioni, consultare il paragrafo “Abilitazione delle sole estensioni essenziali del servizio Web&quot; all'interno di questo capitolo.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Amministrazione remota (HTML)</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce un'interfaccia HTML per l'amministrazione di IIS. Per semplificare l'amministrazione e ridurre la superficie di attacco di un server IIS è consigliabile utilizzare Gestione IIS invece di questo componente. Non è necessario per i server IIS dedicati.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Connessione Web desktop remoto</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Include il controllo Microsoft ActiveX e pagine dimostrative per l'hosting delle connessioni client di Servizi terminal sul Web. Per semplificare l'amministrazione e ridurre la superficie di attacco di un server IIS è consigliabile utilizzare Gestione IIS invece di questo componente. Non è necessario in un server IIS dedicato.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Server – Side Includes</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>Fornisce il supporto per i file con estensione shtm, shtml e stm. Disabilitare questo componente quando nessun sito Web o applicazione in esecuzione nel server IIS include file con queste estensioni.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>WebDAV</p></td>
<td style="border:1px solid black;"><p>Disabilitato</p></td>
<td style="border:1px solid black;"><p>WebDAV estende il protocollo HTTP/1.1 consentendo ai client di pubblicare, bloccare e gestire risorse sul Web. Disabilitare questo componente nei server IIS dedicati o utilizzando le estensioni del servizio Web. Per ulteriori informazioni, consultare il paragrafo “Abilitazione delle sole estensioni essenziali del servizio Web&quot; all'interno di questo capitolo.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Servizio Web</p></td>
<td style="border:1px solid black;"><p>Attivato</p></td>
<td style="border:1px solid black;"><p>Fornisce servizi Web e contenuto statico e dinamico ai client. Il componente è necessario per i server IIS dedicati.</p></td>
</tr>
</tbody>
</table>
  
#### Attivazione delle sole estensioni essenziali dei servizi Web
  
Molte applicazioni e siti Web in esecuzione sui server IIS dispongono di funzionalità estese che vanno oltre le pagine statiche e includono la capacità di generare contenuti dinamici. Per i contenuti dinamici resi disponibili o estesi attraverso caratteristiche fornite da un server IIS vengono utilizzate le estensioni del servizio Web.
  
Le funzionalità di protezione avanzate di IIS 6.0 consentono di attivare o disattivare singole estensioni del servizio Web. Come accennato in precedenza, dopo una nuova installazione i server IIS trasmetteranno solo contenuti statici Le funzionalità relative ai contenuti dinamici possono essere attivate mediante il nodo Estensioni servizio Web di Gestione IIS. Tali estensioni includono ASP.NET, SSI, WebDAV e le estensioni del server di FrontPage.
  
Una soluzione per assicurare la massima compatibilità possibile con le applicazioni esistenti è l'attivazione di tutte le estensioni del servizio Web, ma questo metodo induce anche un elevato rischio di protezione, in quanto aumenta la superficie di attacco di IIS. Si consiglia di attivare solo le estensioni del servizio Web richieste dalle applicazioni e dai siti Web in esecuzione sui server IIS nell'ambiente in uso. Questo approccio riduce al minimo la funzionalità del server e di conseguenza la superficie di attacco di ogni server IIS.
  
Per ridurre il più possibile la superficie di attacco dei server IIS, solo le estensioni del servizio Web necessarie sono attivate sui server IIS dei tre ambienti definiti in questa guida.
  
Nella tabella seguente sono elencate le estensioni del servizio Web predefinite e vengono fornite indicazioni dettagliate sui casi in cui è consigliabile attivarle.
  
**Tabella 9.7 Abilitazione delle estensioni del servizio Web**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Estensione del servizio Web</p></th>
<th><p>Quando abilitare l'estensione</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Active Server Pages</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web e applicazioni in esecuzione nei server IIS includono contenuto ASP.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>ASP.NET v1.1.4322</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web e applicazioni in esecuzione nei server IIS includono contenuto ASP.NET.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Tutte le estensioni CGI sconosciute</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web e applicazioni in esecuzione nei server IIS includono contenuto con estensione CGI sconosciuta.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Tutte le estensioni ISAPI sconosciute</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web e applicazioni in esecuzione nei server IIS includono contenuto con estensione ISAPI sconosciuta.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Estensioni del server di FrontPage 2002</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web in esecuzione nei server IIS utilizzano estensioni FrontPage.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Internet Data Connector (IDC)</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web e applicazioni in esecuzione nei server IIS utilizzano IDC per la visualizzazione di informazioni sul database (questo tipo di contenuto include i file con estensione idc e idx).</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Server Side Includes (SSI)</p></td>
<td style="border:1px solid black;"><p>Uno o più siti Web in esecuzione nei server IIS utilizzano direttive SSI per indicare ai server IIS di inserire contenuto riutilizzabile (ad esempio una barra di spostamento, un'intestazione o un piè di pagina) in diverse pagine Web.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>WebDav (Web Distributed Authoring and Versioning)</p></td>
<td style="border:1px solid black;"><p>Nei server IIS il supporto WebDAV è necessario per consentire ai client di pubblicare e gestire risorse Web in maniera trasparente.</p></td>
</tr>
</tbody>
</table>
  
#### Inserimento di contenuti in un volume dedicato
  
I file per il sito Web predefinito di IIS vengono inseriti nella cartella ***&lt;systemroot&gt;*\\inetpub\\wwwroot** (dove *&lt;systemroot&gt;* corrisponde all'unità in cui è installato il sistema operativo Windows Server 2003).
  
Nei tre ambienti definiti in questa guida, tutti i file e le cartelle che compongono le applicazioni e i siti Web sono collocati in volumi disco dedicati, che sono separati dal sistema operativo. In tal modo, è possibile impedire gli attacchi di attraversamento delle directory con cui un pirata informatico invia delle richieste per un file che si trova all'esterno della struttura di directory di un server IIS.
  
Per esempio, il file Cmd.exe si trova nella cartella ***&lt;systemroot&gt;*\\System32.** Un pirata informatico potrebbe inoltrare una richiesta al seguente percorso:
  
..\\..\\Windows\\system\\cmd.exe
  
nel tentativo di richiamare il prompt dei comandi.
  
Se il contenuto del sito Web si trova in un volume separato, un attacco trasversale alla directory, sferrato come descritto, non funzionerebbe, per due motivi. Primo, le autorizzazioni per il file Cmd.exe sono state ripristinate nell'ambito della build di base di Windows * *Server* *2003 con SP1 che limita l'accesso a un gruppo più ristretto di utenti. Secondo, il file Cmd.exe non sarebbe più contenuto nello stesso volume in cui si trova la root Web, e al momento non esistono metodi noti per accedere a comandi che si trovano su unità diverse utilizzando un attacco di questo tipo.
  
Oltre ai vantaggi relativi alla protezione, anche le attività di amministrazione quali il backup e il ripristino risultano semplificate quando i file e le cartelle delle applicazioni e del sito Web sono collocati in un volume dedicato. Inoltre, l'utilizzo di una unità fisica dedicata contribuisce a ridurre i conflitti di disco sul volume di sistema e a migliorare le prestazioni globali di accesso al disco.
  
#### Impostazione delle autorizzazioni NTFS
  
I computer che eseguono Windows  Server  2003 esaminano le autorizzazioni del file system NTFS per determinare il tipo di accesso di cui un utente o un processo dispongono in relazione a un determinato file o cartella. Si consiglia di assegnare le autorizzazioni NTFS in modo da consentire o negare l'accesso a utenti specifici per quanto riguarda i siti Web sui server IIS dei tre ambienti definiti in questa guida.
  
Le autorizzazioni NTFS influiscono solo sugli account cui è stato concesso o negato l'accesso al contenuto delle applicazioni e del sito Web. Le autorizzazioni NTFS devono essere utilizzate unitamente alle autorizzazioni Web, non come loro sostitutivo. Le autorizzazioni del sito Web influiscono su tutti gli utenti che accedono al sito o applicazione. Se le autorizzazioni Web sono in conflitto con le autorizzazioni NTFS per una directory o file, vengono applicate le impostazioni più restrittive.
  
L'accesso di account anonimi ai siti Web e alle applicazioni dovrebbe essere esplicitamente negato nei casi in cui non è necessario. L'accesso anonimo si verifica quando un utente che non dispone di credenziali autenticate accede alle risorse di rete. Gli account anonimi includono l'account Guest predefinito, il gruppo **Guests** e gli account anonimi di IIS. Inoltre, eliminare eventuali autorizzazioni di altri utenti all'accesso in scrittura, ad eccezione di quelle degli amministratori di IIS.
  
Nella tabella seguente sono fornite alcune raccomandazioni relative alle autorizzazioni NTFS da applicare ai diversi tipi di file in un server IIS. I diversi tipi di file possono essere raggruppati in cartelle separate per semplificare l'applicazione delle autorizzazioni NTFS.
  
**Tabella 9.8 Impostazioni consigliate delle autorizzazioni NTFS**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Tipo file</p></th>
<th><p>Autorizzazioni NTFS raccomandate</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>File CGI (.exe, .dll, .cmd, .pl)</p></td>
<td style="border:1px solid black;"><p>Tutti (esegui)</p>
<p>Amministratori (controllo totale)</p>
<p>Sistema (controllo totale)</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>File script (.asp)</p></td>
<td style="border:1px solid black;"><p>Tutti (esegui)</p>
<p>Amministratori (controllo totale)</p>
<p>Sistema (controllo totale)</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>File di inclusione (.inc, .shtm, .shtml)</p></td>
<td style="border:1px solid black;"><p>Tutti (esegui)</p>
<p>Amministratori (controllo totale)</p>
<p>Sistema (controllo totale)</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Contenuti statici (.txt, .gif, .jpg, .htm, .html)</p></td>
<td style="border:1px solid black;"><p>Tutti (sola lettura)</p>
<p>Amministratori (controllo totale)</p>
<p>Sistema (controllo totale)</p></td>
</tr>
</tbody>
</table>
<p> </p>

#### Impostazione delle autorizzazioni di IIS per il sito Web

Le autorizzazioni relative al sito Web vengono esaminate in IIS per determinare il tipo di azione che può avvenire all'interno di un sito, ad esempio l'accesso all'origine script o l'esplorazione delle directory. Le autorizzazioni relative al sito Web devono essere assegnate in modo da garantire una protezione aggiuntiva per i siti Web su server IIS nei tre ambienti definiti in questa guida.

Le autorizzazioni relative al sito Web possono essere utilizzate unitamente alle autorizzazioni NTFS e configurate per siti, directory e file specifici. A differenza delle autorizzazioni NTFS, le autorizzazioni per i siti Web influiscono su tutti gli utenti che tentano di accedere a un sito Web in esecuzione su un server IIS. Le autorizzazioni per i siti Web possono essere applicate utilizzando lo snap-in Gestione IIS MMC.

Nella tabella seguente sono elencate le autorizzazioni per i siti Web supportate da IIS 6.0 e sono fornite brevi descrizioni che spiegano quando assegnare una determinata autorizzazione a un sito.

**Tabella 9.9 Autorizzazioni di IIS 6.0 per i siti Web**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Autorizzazione sito Web</p></th>
<th><p>Autorizzazione concessa</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Lettura</p></td>
<td style="border:1px solid black;"><p>Gli utenti possono visualizzare il contenuto e le proprietà delle directory o file. Questa autorizzazione è selezionata per impostazione predefinita.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Scrittura</p></td>
<td style="border:1px solid black;"><p>Gli utenti possono modificare il contenuto e le proprietà delle directory o file.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Accesso origine script</p></td>
<td style="border:1px solid black;"><p>Gli utenti possono accedere ai file di origine. Se è attivata la lettura, è possibile leggere l'origine; se è attivata la scrittura, il codice sorgente dello script può essere modificato. L'accesso all'origine script include il codice sorgente degli script. Se né la lettura né la scrittura sono attivate, l'opzione non è disponibile.</p>
<p><strong>Importante</strong>: quando è attivato Accesso origine script, gli utenti potrebbero essere in grado di visualizzare informazioni riservate, ad esempio un nome utente e la password. È inoltre possibile che possano modificare il codice sorgente in esecuzione in un server IIS, compromettendo gravemente la protezione e le prestazioni del server.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Esplorazione directory</p></td>
<td style="border:1px solid black;"><p>Gli utenti possono visualizzare l'elenco dei file e raccolte.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Registrazione visite</p></td>
<td style="border:1px solid black;"><p>Viene creata una voce di registro per ogni visita al sito Web.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Indicizza questa risorsa</p></td>
<td style="border:1px solid black;"><p>Consente al <strong>Servizio di indicizzazione</strong> di indicizzare le risorse, risulta in tal modo possibile eseguire ricerche nelle risorse.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Esecuzione</p></td>
<td style="border:1px solid black;"><p>Le opzioni riportate di seguito determinano il livello di esecuzione degli script da parte degli utenti:</p>
<ul>
<li><p><strong>Nessuno</strong>. Non è consentita l'esecuzione sul server di file eseguibili di script.</p></li>
<li><p><strong>Solo script</strong>. È consentita solo l'esecuzione di script sul server.</p></li>
<li><p><strong>Script e file eseguibili</strong>. Sul server è consentita l'esecuzione sia di script sia di eseguibili.</p></li>
</ul></td>
</tr>
</tbody>
</table>
<p> </p>

#### Configurazione della registrazione IIS

Microsoft raccomanda l'abilitazione della registrazione IIS sui server IIS nei tre ambienti definiti in questa guida.

È possibile creare registri separati per ogni applicazione o sito Web. IIS registra una maggior quantità di informazioni rispetto ai registri eventi e alle funzionalità per il controllo delle prestazioni fornite dal sistema operativo Windows. I registri IIS possono comprendere informazioni quali l'utente che ha visitato il sito, quali parti ha visitato e quando le informazioni sono state visualizzate l'ultima volta. I registri IIS possono essere utilizzati per valutare il gradimento dei contenuti, identificare i colli di bottiglia delle informazioni oppure come risorsa per esaminare gli attacchi.

Lo snap-in Gestione IIS MMC può essere utilizzato per configurare il formato dei file di registro, la pianificazione dei registri e quali informazioni registrare. Per limitare la dimensione dei registri, è consigliabile utilizzare un accurato processo di pianificazione per stabilire quali campi registrare.

Una volta attivata la registrazione IIS, viene utilizzato il formato di file registro W3C esteso per creare registri delle attività giornaliere nella directory specificata per il sito Web in Gestione IIS. Per migliorare le prestazioni del server, è consigliabile memorizzare i registri in un volume non di sistema con striping o con striping/mirroring.

I registri possono inoltre essere scritti su una condivisione di rete remota utilizzando un percorso UNC (Universal Naming Convention). La registrazione remota consente agli amministratori di impostare l'archiviazione e il backup centralizzato dei file di registro. Tuttavia, la scrittura dei file di registro sulla rete potrebbe ripercuotersi negativamente sulle prestazioni del server.

La registrazione IIS può essere configurata in modo da utilizzare diversi altri file di registro ASCII o ODBC (Open Database Connectivity). I registri ODBC consentono di memorizzare le informazioni relative all'attività in un database SQL. Tuttavia, si noti che, quando è attivata la registrazione ODBC, IIS disattiva la cache in modalità kernel, operazione che potrebbe causare un degrado delle prestazioni globali del server.

I server IIS che ospitano centinaia di siti possono attivare la registrazione binaria centralizzata per migliorare le prestazioni di registrazione. La registrazione binaria centralizzata fa sì che le informazioni relative all'attività di tutti i siti Web presenti in un server IIS vengano scritte in un unico file di registro. Questo metodo può aumentare notevolmente la gestibilità e la scalabilità del processo di registrazione di IIS, riducendo il numero dei registri da memorizzare e analizzare singolarmente. Per ulteriori informazioni sulla registrazione binaria centralizzata, visitare la pagina [Registrazione binaria centralizzata IIS](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/13a4c0b5-686b-4766-8729-a3402da835f1.mspx) sul sito www.microsoft.com/technet/prodtechnol
/ WindowsServer2003/Library/IIS/13a4c0b5-686b-4766-8729-a3402da835f1.mspx.

Quando i registri IIS sono memorizzati su server IIS, per impostazione predefinita solo gli amministratori del server hanno l'autorizzazione ad accedervi. Se il proprietario di un file o directory di file di registro non fa parte del gruppo degli amministratori locali, il file HTTP.sys (il driver in modalità kernel di IIS 6.0) pubblica un errore nel registro eventi NT. Questo errore indica che il proprietario della directory o file non fa parte del gruppo degli amministratori locali e che la registrazione per il sito resterà sospesa finché non si aggiunge il proprietario al gruppo degli amministratori locali, o finché la directory o file di registro esistente non viene eliminato.

#### Aggiunta manuale di gruppi di protezione univoci ad Assegnazioni diritti utente

Per la maggior parte delle assegnazioni di diritti utente applicate tramite i criteri MSBP, i gruppi di protezione sono specificati nei modelli di protezione allegati a questa guida. Vi sono, tuttavia, alcuni account e gruppi di protezione che non è stato possibile includere nei modelli, perché i relativi ID di protezione (SID) sono specifici di singoli domini Windows 2003. Le assegnazioni dei diritti utente che devono essere configurati manualmente sono specificate nella seguente tabella.

Avvertenza: nella tabella che segue sono contenuti i valori per l'account **Amministratore** incorporato. Non confondere l'account Amministratore col gruppo di protezione **Amministratori** incorporato. Se si aggiunge il gruppo di protezione **Amministratori** a uno qualunque dei diritti di accesso utente negati, sarà necessario accedere a livello locale per correggere l'errore.

Inoltre, è possibile che l'account Amministratore incorporato sia stato rinominato in base ai consigli del Capitolo 4, "Criterio di base per un server membro". Quando si aggiunge l'account Amministratore a uno qualunque dei diritti utente, assicurarsi di specificare l'account rinominato.

**Tabella 9.10 Assegnazioni diritti utente aggiunte manualmente**

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
<th><p>Impostazione predefinita server membro</p></th>
<th><p>Legacy Client</p></th>
<th><p>Enterprise Client</p></th>
<th><p>Specialized Security – Limited Functionality</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Nega accesso al computer dalla rete</p></td>
<td style="border:1px solid black;"><p>Amministratore incorporato; Support_388945a0;</p>
<p>Guest; Tutti gli account di servizio NON utilizzati dal sistema operativo</p></td>
<td style="border:1px solid black;"><p>Amministratore incorporato; Support_388945a0;</p>
<p>Guest; Tutti gli account di servizio NON utilizzati dal sistema operativo</p></td>
<td style="border:1px solid black;"><p>Amministratore incorporato; Support_388945a0;</p>
<p>Guest; Tutti gli account di servizio NON utilizzati dal sistema operativo</p></td>
</tr>
</tbody>
</table>
<p> </p>

**Importante:** l'opzione “Tutti gli account di servizio NON utilizzati dal sistema operativo" comprende gli account di servizio usati per applicazioni specifiche all'interno di un'organizzazione, ma NON comprende gli account SISTEMA LOCALE, SERVIZIO LOCALE o quelli del SERVIZIO DI RETE (gli account predefiniti usati dal sistema operativo).

#### Protezione di account noti

In Windows Server 2003 sono disponibili alcuni account utente incorporati che non possono essere eliminati, ma che è possibile rinominare. Due degli account predefiniti più noti di Windows Server 2003 sono Guest e Amministratore.

Per impostazione predefinita, l'account Guest è disabilitato nei server membri e nei controller di dominio. Questa impostazione non deve essere modificata. Molte varianti di codice nocivo utilizzano l'account predefinito Administrator nel primo tentativo di attacco a un server. È quindi necessario rinominare l'account Amministratore incorporato e modificarne la descrizione per evitare la compromissione dei server remoti da parte di pirati informatici che cercano di usare questo account noto.

Negli ultimi anni il valore della modifica di questa configurazione è diminuito, a seguito della comparsa di strumenti di attacco che cercano di penetrare nel server specificando l'ID di protezione dell'account Amministratore incorporato, per scoprirne il vero nome e quindi penetrare nel server. Il SID è il valore che identifica in modo univoco un utente, un gruppo, un account di computer e una sessione di accesso in una rete. Non è possibile modificare il SID di questo account incorporato. Tuttavia, i gruppi operativi possono controllare facilmente i tentativi di attacco contro questo account Amministratore, se viene rinominato con un nome esclusivo.

**Per proteggere gli account noti sui server IIS**

-   Rinominare gli account Amministratore e Guest e modificarne le password impostando valori lunghi e complessi in tutti i domini e server.

-   Utilizzare nomi e password diversi su ciascun server. Se si utilizzano gli stessi nomi account e password in tutti i domini e server, un pirata informatico in grado di accedere a un server membro potrà avvalersi dello stesso nome account e password per accedere a tutti gli altri server.

-   Modificare le descrizioni predefinite degli account per ostacolarne l'identificazione.

-   Salvare qualsiasi modifica effettuata in un luogo sicuro.

    **Nota**: è possibile rinominare l’account amministratore incorporato mediante i Criteri di gruppo. Questa impostazione di criterio non è stata implementata in nessuno dei modelli di protezione forniti con questa guida, in quanto ogni organizzazione deve scegliere un nome esclusivo per questo account. Tuttavia, è possibile configurare le impostazioni di **Account: rinomina l'account amministratore** per rinominare gli account amministratore in tutti e tre gli ambienti definiti in questa guida. Questa impostazione fa parte delle Opzioni di protezione di un GPO.

#### Protezione degli account di servizio

Se non è inevitabile, si sconsiglia di configurare un servizio per l'esecuzione in un contesto di protezione di un account di dominio. Se il server è danneggiato, è possibile ottenere facilmente le password degli account di dominio eseguendo il dump dei segreti dell'autorità di protezione locale (LSA, Local Security Authority). Per ulteriori informazioni su come proteggere gli account di servizio, consultare anche la guida [Guida alla pianificazione della protezione degli account dei servizi](http://technet.microsoft.com/it-it/library/cc170953) (in inglese) all'indirizzo www.microsoft.com/technet/security/topics/serversecurity/serviceaccount/default.mspx.

[](#mainsection)[Inizio pagina](#mainsection)

### Creazione del criterio utilizzando SCW

Per distribuire le impostazioni di protezione necessarie è necessario utilizzare sia la Configurazione guidata impostazioni di sicurezza (SCW) sia i modelli di protezione forniti con la versione scaricabile di questa guida per creare un criterio di server.

Quando si crea un proprio criterio, ignorare le sezioni "Impostazioni di registro" e “Criterio di controllo”. Queste impostazioni sono fornite dai modelli di protezione per l'ambiente prescelto. Questo approccio garantisce che gli elementi di criterio forniti dai modelli abbiano la precedenza su quelli che verranno configurati da SCW.

Per iniziare il lavoro di configurazione, in modo da garantire che non vi siano impostazioni o software legacy di configurazioni precedenti, utilizzare un'installazione nuova del sistema operativo. Se possibile, per garantire la massima compatibilità, utilizzare un hardware simile a quello usato durante la distribuzione. L'installazione nuova è chiamata *computer di riferimento.*

**Per creare i criteri del server IIS**

1.  Creare una nuova installazione di Windows Server 2003 con SP1 su un computer di riferimento nuovo.

2.  Installare il componente di Configurazione guidata impostazioni di sicurezza (SCW) sul computer tramite il Pannello di controllo, Aggiungi/rimuovi programmi, Aggiungi/rimuovi componenti di Windows.

3.  Aggiungere il computer al dominio, che applicherà tutte le impostazioni di protezione dalle unità operative genitore.

4.  Installare e configurare soltanto le applicazioni obbligatorie che saranno presenti su ogni server che condivide questo ruolo. Gli esempi comprendono servizi specifici, agenti di software e di gestione, agenti di backup su nastro e utilità antivirus o antispyware.

5.  Lanciare la SCW GUI, selezionare **Crea il nuovo criterio**, e scegliere il computer di riferimento.

6.  Verificare che i ruoli dei server rilevati siano appropriati per l'ambiente in uso — ad esempio i ruoli di server applicazioni e server Web.

7.  Accertarsi che le funzionalità client rilevate siano adatte all'ambiente in uso.

8.  Accertarsi che le funzionalità client rilevate siano adatte all'ambiente in uso.

9.  Assicurarsi che tutti i servizi aggiuntivi richiesti per l'implementazione di base, come agenti di backup o software antivirus, siano rilevati.

10. Decidere come gestire i servizi non specificati nell'ambiente in uso. Per una maggior protezione, è possibile configurare questa impostazione di criterio su **Disattiva.** Verificare questa configurazione prima di implementarla nella rete di produzione, in quanto potrebbe causare problemi se i server di produzione eseguono servizi aggiuntivi che non sono duplicati sul computer di riferimento.

11. Accertarsi che la casella **Salta questa sezione** non sia selezionata nella sezione "Protezione di rete" e fare clic su **Avanti.** Le porte e le applicazioni identificate in precedenza vengono configurate come eccezioni per Windows Firewall.

12. Nella sezione "Impostazioni di registro", fare clic sulla casella di controllo **Salta questa sezione** e quindi su **Avanti.** Queste impostazioni di criterio sono importate dal file INF fornito.

13. Nella sezione "Criterio di controllo", fare clic sulla casella di controllo **Salta questa sezione** e quindi su **Avanti**. Queste impostazioni di criterio sono importate dal file INF fornito.

14. Allegare il modello di protezione idoneo (ad esempio, EC-IIS Server.inf).

15. Salvare il criterio con un nome idoneo (ad esempio, IIS Server.xml).

    **Nota**: in base ai criteri MSBP vengono disattivati diversi altri servizi correlati a IIS, inclusi FTP, SMTP, e NNTP. È necessario modificare i criteri del server Web per poter attivare uno di questi servizi sui server IIS in uno dei tre ambienti definiti in questa guida.

#### Verificare il criterio utilizzando SCW

Dopo aver creato e salvato il criterio, Microsoft consiglia di usarlo per verificare l'ambiente di prova. Idealmente, i server di prova avranno la medesima configurazione di hardware e software dei server di produzione. Questo approccio consentirà di trovare e riparare potenziali problemi, come la presenza di servizi imprevisti richiesti da specifiche periferiche hardware.

Per verificare il criterio sono disponibili due opzioni. È possibile utilizzare le funzionalità di sviluppo SCW native, o implementare i criteri tramite un GPO.

Quando si iniziano a creare i criteri, prendere in considerazione l'utilizzo di funzionalità di sviluppo SCW native. È possibile utilizzare SCW per inviare un criterio a un unico server per volta, oppure Scwcmd per inviare il criterio a un gruppo di server. Il metodo di sviluppo nativo consente di rieseguire facilmente i criteri utilizzati da SCW. Questa funzionalità può essere molto utile quando si apportano modifiche multiple ai criteri, durante il processo di prova.

Il criterio è verificato per accertarsi che la sua applicazione a server di destinazione non ne comprometta le funzioni critiche. Dopo aver applicato le modifiche alla configurazione, è necessario iniziare a verificare la funzionalità di base del computer. Per esempio, se il server è configurato come un'autorità di certificazione (CA), accertarsi che i client possano richiedere e ottenere dei certificati, scaricare un elenco di revoche di certificati e così via.

Quando si è certi delle proprie configurazioni di criterio, è possibile utilizzare Scwcmd come mostrato nella seguente procedura per convertire i criteri in GPO.

Per ulteriori dettagli su come verificare i criteri di SCW, consultare la guida [Deployment Guide for the Security Configuration Wizard](http://technet.microsoft.com/en-us/library/cc776871.aspx) (in inglese) all'indirizzo www.microsoft.com/technet/prodtechnol/windowsserver2003/
library/SCWDeploying/5254f8cd-143e-4559-a299-9c723b366946.mspx* * e la guida [Security Configuration Wizard Documentation](http://go.microsoft.com/fwlink/?linkid=43450)(in inglese) all'indirizzo http://go.microsoft.com/fwlink/?linkid=43450.

#### Conversione e utilizzo del criterio

Dopo aver verificato a fondo il criterio, completare le seguenti fasi, per trasformarlo in un GPO e utilizzarlo:

1.  Al prompt dei comandi digitare il seguente comando:
        ```

    e premere INVIO. Ad esempio:
        ```

    **Nota**: le informazioni che devono essere inserite al prompt dei comandi occupano qui più di una riga a causa delle limitazioni del display. Queste informazioni dovrebbero essere inserite tutte su una riga.

2.  Utilizzare la Console di gestione Criteri di gruppo per collegare il GPO appena creato all'unità operativa adeguata.

Se il file dei criteri di protezione di SCW contiene le impostazioni di Windows Firewall, Windows Firewall dovrà essere attivo sul computer locale, affinché questa procedura possa essere completata con successo. Per verificare che Windows Firewall sia attivo, aprire il Pannello di controllo e fare doppio clic su **Windows Firewall**.

Eseguire ora una prova finale per accertarsi che il GPO applichi le impostazioni desiderate. Per completare questa procedura, confermare sia l'esecuzione delle impostazioni appropriate sia l'integrità della funzionalità.

[](#mainsection)[Inizio pagina](#mainsection)

### Riepilogo

Il presente capitolo ha descritto le impostazioni di criterio che possono essere utilizzate per rafforzare i server IIS che eseguono Windows Server 2003 con SP1 nei tre ambienti definiti in questa guida. La maggior parte delle impostazioni sono applicate tramite un oggetto Criteri di gruppo (GPO) che era stato progettato per completare il criterio MSBP. Per fornire maggiore sicurezza, è possibile collegare i GPO alle unità organizzative (OU) appropriate che contengono i server IIS.

Alcune delle impostazioni trattate non possono essere applicate mediante i Criteri di gruppo. Per queste impostazioni, sono stati forniti dei dettagli per la configurazione manuale.

#### Ulteriori informazioni

I seguenti collegamenti forniscono informazioni aggiuntive sulla protezione avanzata di server Web basati su IIS che eseguono Windows Server 2003 con SP1.

-   Per informazioni su come attivare la registrazione IIS, consultare l'articolo della Microsoft Knowledge Base "[Come attivare la registrazione in Internet Information Services](http://support.microsoft.com/kb/313437/it)" all'indirizzo http://support.microsoft.com/kb/313437/it.

-   Ulteriori informazioni sulla registrazione sono disponibili alla pagina [Enable Logging (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/d29207e8-5274-4f4b-9a00-9433b73252d6.mspx) all'indirizzo www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/
    d29207e8-5274-4f4b-9a00-9433b73252d6.mspx (in inglese).

-   Per le informazioni sull'attività di registrazione del sito, consultare la pagina [Logging Site Activity (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/ab7e4070-e185-4110-b2b1-1bcac4b168e0.mspx) all'indirizzo www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/
    IIS/ab7e4070-e185-4110-b2b1-1bcac4b168e0.mspx (in inglese).

-   Per informazioni sulla registrazione estesa, consultare la pagina [Customizing W3C Extended Logging (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/96af216b-e2c0-428e-9880-95cbd85d90a1.mspx) all'indirizzo www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/
    IIS/96af216b-e2c0-428e-9880-95cbd85d90a1.mspx (in inglese).

-   Per informazioni sulla registrazione binaria centralizzata, consultare la pagina [Centralized Binary Logging in IIS 6.0 (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/b9cdc076-403d-463e-9a36-5a14811d34c7.mspx) su Microsoft.Com all'indirizzo www.microsoft.com/technet/prodtechnol/
    WindowsServer2003/Library/IIS/b9cdc076-403d-463e-9a36-5a14811d34c7.mspx (in inglese).

-   Ulteriori informazioni sulla registrazione sono disponibili alla pagina [Remote Logging (IIS 6.0)](http://www.microsoft.com/technet/prodtechnol/windowsserver2003/library/iis/a6347ae3-39d1-4434-97c9-5756e5862c61.mspx) all'indirizzo www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/
    a6347ae3-39d1-4434-97c9-5756e5862c61.mspx (in inglese).

-   Per ulteriori informazioni su IIS 6.0, consultare la pagina [Internet Information Services](http://www.microsoft.com/windowsserver2003/iis/default.mspx) all'indirizzo www.microsoft.com/WindowsServer2003/iis/default.mspx (in inglese).

**Download**

[Utilizzo della Guida per la protezione di Windows Server 2003](http://www.microsoft.com/downloads/details.aspx?familyid=8a2643c1-0685-4d89-b655-521ea6c7b4db&displaylang=en)

**Notifiche di aggiornamento**

[Iscriversi per ottenere aggiornamenti e nuove versioni](http://go.microsoft.com/fwlink/?linkid=54982)

**Commenti e suggerimenti**

[Inviare commenti o suggerimenti](mailto:%20secwish@microsoft.com?subject=guida%20per%20la%20protezione%20di%20windows%20server%202003)

[](#mainsection)[Inizio pagina](#mainsection)
