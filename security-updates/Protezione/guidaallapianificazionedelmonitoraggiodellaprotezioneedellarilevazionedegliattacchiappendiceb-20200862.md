---
TOCTitle: 'Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi - Appendice B'
Title: 'Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi - Appendice B'
ms:assetid: 'e0124920-4edd-4629-9251-3d89b16240c7'
ms:contentKeyID: 20200862
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Dd536263(v=TechNet.10)'
---

Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi
==============================================================================================

### Appendice B - Implementazione delle impostazioni Criteri di gruppo

Aggiornato: 23 maggio 2005

Nella seguente tabella sono elencate le impostazioni da applicare per la corretta configurazione delle impostazioni dei controlli di protezione di Criteri di gruppo. Sono inoltre indicate le impostazioni aggiuntive che hanno effetto sul sistema di monitoraggio della protezione e di rilevazione degli attacchi. Utilizzare questa tabella per verificare le impostazioni correnti nell'ambiente in uso.

**Tabella B.1. Impostazioni dei controlli di protezione di Criteri di gruppo**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Percorso criterio</p></th>
<th><p>Criterio</p></th>
<th><p>Impostazione del criterio e commenti</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla eventi accesso account</strong></p></td>
<td style="border:1px solid black;"><p>Attivare il controllo sulle operazioni riuscite per tutti i computer, poiché questo evento registra gli utenti che accedono al computer. L'attivazione del controllo sulle operazioni non riuscite deve essere effettuata con cautela. Un utente malintenzionato con accesso alla rete ma senza alcuna credenziale potrebbe infatti causare un attacco di tipo Denial of Service (DoS), poiché il computer utilizza risorse per generare questi eventi. Fare attenzione nell'attivazione del controllo sulle operazioni riuscite, poiché questa impostazione può causare attacchi di tipo DoS se è previsto l'arresto dei computer in caso di riempimento dei registri di controllo. Mettere in relazione gli accessi amministratore con qualsiasi altra voce sospetta.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla gestione degli account</strong></p></td>
<td style="border:1px solid black;"><p>Attivare il controllo sia sulle operazioni riuscite che non riuscite. Mettere in relazione tutte le voci di controllo relative alle operazioni riuscite con le autorizzazioni di amministratore. Considerare tutte le operazioni non riuscite come eventi sospetti.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla accesso al servizio directory</strong></p></td>
<td style="border:1px solid black;"><p>Questa impostazione è attivata automaticamente dal Criterio di gruppo controller di dominio predefiniti. Configurare le impostazioni di controllo sugli oggetti directory sensibili utilizzando gli elenchi di controllo accesso di sistema (SACL) in Utenti e computer di Active Directory o Active Directory Services Interface Editor (ADSI Edit). Una volta pianificata l'implementazione SACL, prima della distribuzione in un ambiente di produzione è necessario testare gli elenchi SACL in un ambiente di lavoro realistico. Questo approccio evita di sovraccaricare i registri di protezione con una quantità eccessiva di dati.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla eventi di accesso</strong></p></td>
<td style="border:1px solid black;"><p>Attivare il controllo sulle operazioni riuscite per tutti i computer, poiché questo evento registra gli utenti che accedono al computer. L'attivazione del controllo sulle operazioni non riuscite deve essere effettuata con cautela. Un utente malintenzionato con accesso alla rete ma senza alcuna credenziale potrebbe infatti causare l'utilizzo di risorse per generare questi eventi.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla accesso agli oggetti</strong></p></td>
<td style="border:1px solid black;"><p>Fare attenzione quando si attiva questa impostazione poiché potrebbe causare un volume molto elevato di controlli. Configurare le impostazioni di controllo solo sulle cartelle critiche mediante elenchi SACL e controllare soltanto il numero minimo dei tipi di accesso a cui si è interessati. Se il modello di rischio lo consente, controllare soltanto le scritture (non gli accessi in lettura).</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Modifica del criterio di controllo</strong></p></td>
<td style="border:1px solid black;"><p>Attivare il controllo sia sulle operazioni riuscite che non riuscite. Mettere in relazione eventuali operazioni riuscite con le autorizzazioni di amministratore. Considerare tutte le operazioni non riuscite come eventi sospetti.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla uso dei privilegi</strong></p></td>
<td style="border:1px solid black;"><p>Si consiglia di non attivare questo controllo a causa del volume elevato di eventi generato.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla tracciato processo</strong></p></td>
<td style="border:1px solid black;"><p>Non attivare questa impostazione nei server Web Common Gateway Interface (CGI), nei computer di test, nei server su cui sono in esecuzione processi batch o nelle workstation degli sviluppatori. Attivare questa impostazione nei computer vulnerabili e intervenire immediatamente in caso di attività impreviste nelle applicazioni, se necessario mediante l'isolamento fisico del computer. Questa impostazione può causare il riempimento dei registri di eventi.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/</p>
<p>Criteri di controllo</p></td>
<td style="border:1px solid black;"><p><strong>Controlla eventi di sistema</strong></p></td>
<td style="border:1px solid black;"><p>Attivare il controllo sia sulle operazioni riuscite che non riuscite.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/ Assegnazione diritti utente</p></td>
<td style="border:1px solid black;"><p><strong>Generazione di controlli di protezione</strong></p></td>
<td style="border:1px solid black;"><p>Questa impostazione viene assegnata automaticamente agli account Sistema locale, Servizio locale e Servizio di rete. Questo diritto deve essere applicato soltanto agli account dei servizi. Un utente malintenzionato può utilizzare questa impostazione per generare eventi falsi o inesatti nel registro di protezione.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/ Assegnazione diritti utente</p></td>
<td style="border:1px solid black;"><p><strong>Gestione file registro di controllo e di protezione</strong></p></td>
<td style="border:1px solid black;"><p>Utilizzare questa impostazione per impedire agli amministratori con diritti di modifica di controllare le impostazioni relative ai file, alle cartelle e al Registro di sistema. Prendere in considerazione la creazione di un gruppo di protezione per gli amministratori che possono apportare modifiche alle impostazioni di controllo, quindi rimuovere il gruppo Administrators dalle impostazioni di Criteri di protezione locali. Soltanto i membri del nuovo gruppo di protezione devono essere in grado di configurare le impostazioni di controllo.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/ Opzioni di protezione</p></td>
<td style="border:1px solid black;"><p><strong>Controllo: controllo accesso oggetti di sistema globale</strong></p></td>
<td style="border:1px solid black;"><p>Questa impostazione aggiunge elenchi SACL a determinati oggetti di sistema quali eventi di esclusione reciproca, semafori e periferiche MS-DOS. Per impostazione predefinita, in Windows Server 2003 questa opzione non è attivata. Si consiglia di non attivare questa impostazione, poiché causa la generazione di un numero molto elevato di eventi.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Criteri locali/ Opzioni di protezione</p></td>
<td style="border:1px solid black;"><p><strong>Controllo: controllo utilizzo dei privilegi di backup e di ripristino</strong></p></td>
<td style="border:1px solid black;"><p>Le operazioni di backup e ripristino forniscono l'opportunità di appropriarsi di dati protetti dagli ACL. Si consiglia di non attivare questa impostazione, poiché causa la generazione di un numero molto elevato di eventi.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Criteri locali/ Opzioni di protezione</p></td>
<td style="border:1px solid black;"><p><strong>Controllo: arresto del sistema immediato se non è possibile registrare i controlli di protezione</strong></p></td>
<td style="border:1px solid black;"><p>Attivare questa impostazione, dopo un'attenta analisi, soltanto sui computer critici, poiché gli utenti malintenzionati possono utilizzare questa funzionalità per attacchi di tipo DoS.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Registro eventi</p></td>
<td style="border:1px solid black;"><p><strong>Dimensione massima registro protezione</strong></p></td>
<td style="border:1px solid black;"><p>La dimensione massima del registro di protezione deve essere un multiplo di 64 KB. La dimensione media degli eventi è 0,5 KB. Le impostazioni consigliate dipendono dai volumi previsti per gli eventi e dalle impostazioni relative alla gestione dei registri di protezione. Per gli ambienti in cui viene generato un numero elevato di eventi, è preferibile impostare il valore più grande possibile (fino a 250 MB). Poiché la dimensione totale di tutti i registri di eventi non può superare 300 MB, è necessario non superare questo valore.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Registro eventi</p></td>
<td style="border:1px solid black;"><p><strong>Impedisci accesso guest locale al registro applicazione</strong></p></td>
<td style="border:1px solid black;"><p>Per impostazione predefinita, in Windows Server 2003 questa opzione è attivata e non deve essere modificata.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Registro eventi</p></td>
<td style="border:1px solid black;"><p><strong>Gestione registro protezione</strong></p></td>
<td style="border:1px solid black;"><p>Questa impostazione deve essere attivata solo se è selezionata l'opzione Sovrascrivi eventi ogni giorno. Se si utilizza un sistema di correlazione basato sul polling degli eventi, assicurarsi che il numero dei giorni sia almeno il triplo della frequenza di polling, in modo da consentire cicli di polling non riusciti.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Registro eventi</p></td>
<td style="border:1px solid black;"><p><strong>Criteri gestione registro protezione</strong></p></td>
<td style="border:1px solid black;"><p>Negli ambienti con requisiti di protezione elevati si consiglia di attivare l'opzione Non sovrascrivere eventi. In questo caso, occorre definire procedure per lo svuotamento e l'archiviazione periodica dei registri, in particolare se è previsto l'arresto del computer in caso di riempimento del registro di protezione.</p></td>
</tr>
</tbody>
</table>
  
##### Download
  
[![](images/Dd536263.icon_exe(it-it,TechNet.10).gif)Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi](http://go.microsoft.com/fwlink/?linkid=41310)
  
[](#mainsection)[Inizio pagina](#mainsection)
