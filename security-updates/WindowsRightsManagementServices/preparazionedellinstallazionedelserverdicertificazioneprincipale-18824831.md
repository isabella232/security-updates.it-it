---
TOCTitle: 'Preparazione dell''installazione del server di certificazione principale'
Title: 'Preparazione dell''installazione del server di certificazione principale'
ms:assetid: 'ed51605e-8b17-4155-8d83-f6777f499b7b'
ms:contentKeyID: 18824831
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747726(v=WS.10)'
---

Preparazione dell'installazione del server di certificazione principale
=======================================================================

Nell'installazione di verifica esemplificativa è stato utilizzato un solo server di certificazione principale. Se lo si desidera, è possibile configurare server aggiuntivi come parte di un cluster di certificazione principale, oppure come cluster di server licenze separato. La configurazione dell'infrastruttura di tutti i server di questo tipo è la stessa e sarà pertanto necessario seguire la procedura specificata in questo argomento in tutti questi server.

Dopo aver installato il controller di dominio e configurato i server di database (come descritto nella sezione precedente) e aver completato i passaggi della tabella seguente, si sarà pronti per installare RMS.

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
<th>Per preparare il server per l'installazione di RMS</th>
<th>Note per la distribuzione in un ambiente di produzione</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Sistema operativo</p></td>
<td style="border:1px solid black;"><p>Su un computer che soddisfa i requisiti hardware di RMS, ma che non è ancora collegato a una rete, installare il sistema operativo Windows Server 2003 e utilizzare il file system NTFS per la partizione.</p></td>
<td style="border:1px solid black;"><p>È consigliabile installare sempre il service pack e le patch più recenti. Utilizzare partizioni formattate con NTFS.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Connessione a Internet</p>
<p>(facoltativo)</p></td>
<td style="border:1px solid black;"><p>Creare una connessione Ethernet a una rete che fornisce la connettività Internet ma è isolata dall'ambiente di produzione. Se si utilizzerà la registrazione in linea per registrare il server RMS come parte del processo di provisioning, il server deve disporre di connettività Internet.</p></td>
<td style="border:1px solid black;"><p>Se si utilizza la registrazione in linea, assicurarsi che la connessione Internet disponga di un firewall appropriato.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Indirizzo IP</p></td>
<td style="border:1px solid black;"><p>Assegnare un indirizzo IP statico a questo computer.</p></td>
<td style="border:1px solid black;"><p>Utilizzare sempre indirizzi IP statici per i server.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Aggiunta del computer al dominio</p></td>
<td style="border:1px solid black;"><p>Accedere al computer come amministratore locale. Fare clic sul pulsante <strong>Start</strong>, fare clic con il pulsante destro del mouse su <strong>Risorse del computer</strong>, scegliere <strong>Proprietà</strong>, selezionare la scheda <strong>Nome computer</strong>, quindi fare clic su <strong>Cambia</strong>.</p></td>
<td style="border:1px solid black;"><p>Utilizzare lo stesso dominio per tutti i server.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Lasciare inalterato il nome di computer, fare clic su <strong>Dominio</strong>, quindi digitare il nome del dominio, ad esempio Industrieharper.com, e scegliere <strong>OK</strong>. Specificare le credenziali dell'utente che consentono di aggiungere il computer al dominio, scegliere <strong>OK</strong>, quindi riavviare il computer quando richiesto. Dopo il riavvio del computer e la richiesta delle credenziali di accesso, specificare il dominio, il nome utente e la password appropriati.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Utente e accesso</p></td>
<td style="border:1px solid black;"><p>Fare clic con il pulsante destro del mouse su <strong>Risorse del computer</strong>, scegliere <strong>Gestione</strong>, espandere <strong>Utenti e gruppi locali</strong>, fare clic su <strong>Gruppi</strong> e quindi doppio clic su <strong>Administrators</strong>.</p>
<p>Fare clic su <strong>Aggiungi</strong>, specificare il nome dell'account utente da aggiungere, ad esempio Zaffaroni@industrieharper.com, quindi scegliere <strong>OK</strong>. Assegnare all'account utente i privilegi di amministratore. Quando vengono richieste le credenziali, specificare i dati appropriati, ad esempio Industrieharper\Administrator.</p>
<p>Accedere al computer come utente del dominio con privilegi di amministratore.</p></td>
<td style="border:1px solid black;"><p>I diritti di amministratore sono necessari per aggiungere componenti a questo computer. Alcuni passaggi dell'installazione non possono essere completati utilizzando l'account di amministratore locale. È necessario che almeno un utente del dominio in questo server sia un amministratore. Inoltre, SQL Server richiede i diritti di amministratore del sistema per la creazione di nuovi database.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Connessione a Internet</p>
<p>(facoltativo)</p></td>
<td style="border:1px solid black;"><p>Utilizzando un browser Internet, accedere all'indirizzo http://uddi.microsoft.com/ per verificare l'accesso a Internet. Su computer che eseguono Windows Server 2003, è possibile che i file Lmhosts e Hosts debbano essere modificati in modo da includere il controller di dominio.</p></td>
<td style="border:1px solid black;"><p>Connettersi al sito http://uddi.microsoft.com per verificare l'accesso a Internet.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Attivazione di Windows</p></td>
<td style="border:1px solid black;"><p>Per attivare Windows presso Microsoft, è possibile utilizzare l'attivazione guidata utilizzando una connessione Internet oppure attivare Windows mediante contatto telefonico. Per ulteriori informazioni sull'attivazione del prodotto Windows Server 2003, vedere Guida in linea e supporto tecnico di Windows Server 2003.</p></td>
<td style="border:1px solid black;"><p>Windows Server 2003 deve essere attivato entro 14 giorni dall'installazione.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Aggiornamenti del software</p></td>
<td style="border:1px solid black;"><p>Assicurarsi di aver installato gli ultimi aggiornamenti del software installato sul computer.</p></td>
<td style="border:1px solid black;"><p>Installare gli ultimi aggiornamenti software.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Configurazione di Internet Explorer</p></td>
<td style="border:1px solid black;"><p>RMS utilizza un'interfaccia Web per l'amministrazione. Alcune delle impostazioni di protezione predefinite possono impedire la corretta visualizzazione delle pagine. Alcune pagine nel sito Amministrazione Web RMS utilizzano finestre popup per alcune opzioni di configurazione.</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
</tbody>
</table>
  
Una volta terminati tutti i passaggi precedenti su entrambi i server, si è pronti per installare RMS ed eseguirne il provisioning sui server.
