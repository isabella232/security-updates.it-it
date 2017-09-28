---
TOCTitle: 'Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi - Appendice A'
Title: 'Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi - Appendice A'
ms:assetid: '2a358239-864f-40aa-8427-45fed1a0c7c1'
ms:contentKeyID: 20200861
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Dd536262(v=TechNet.10)'
---

Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi
==============================================================================================

### Appendice A - Esclusione degli eventi superflui

Aggiornato: 23 maggio 2005

Nella seguente tabella sono elencati gli eventi che in genere vengono esclusi dai controlli del monitoraggio della protezione perché si verificano molto raramente e non forniscono inoltre alcuna informazione utile.

**Nota: **l'esclusione di qualsiasi informazione da un controllo implica ovviamente un aumento del rischio. Questo aspetto, tuttavia, deve essere valutato rispetto alla frequenza degli eventi e al carico di lavoro risultante sull'agente di analisi.

**Tabella A.1. Riduzione del carico di lavoro sul sistema di archiviazione mediante la rimozione di eventi**

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th><p>ID evento</p></th>
<th><p>Occorrenza</p></th>
<th><p>Commenti</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>538</p></td>
<td style="border:1px solid black;"><p>Fine sessione dell'utente</p></td>
<td style="border:1px solid black;"><p>Questo evento non indica necessariamente il momento in cui l'utente ha smesso di utilizzare il computer. Se ad esempio l'utente spegne il computer senza prima disconnettersi oppure si verifica un'interruzione nella connessione di rete a una condivisione, è possibile che nel computer l'operazione di disconnessione non venga registrata affatto o che venga registrata solo quando il computer rileva che la connessione è interrotta.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>551</p></td>
<td style="border:1px solid black;"><p>Disconnessione avviata dall'utente</p></td>
<td style="border:1px solid black;"><p>Utilizzare l'evento 538, che consente di verificare la disconnessione.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>562</p></td>
<td style="border:1px solid black;"><p>Handle di oggetto chiuso</p></td>
<td style="border:1px solid black;"><p>Questo evento viene sempre registrato come operazione riuscita.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>571</p></td>
<td style="border:1px solid black;"><p>Contesto client eliminato da Gestione autorizzazioni</p></td>
<td style="border:1px solid black;"><p>Si tratta di un evento normale quando si utilizza Gestione autorizzazioni.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>573</p></td>
<td style="border:1px solid black;"><p>Generazione di un evento di controllo non di sistema con API di autorizzazione (Authorization Application Programming Interface)</p></td>
<td style="border:1px solid black;"><p>Comportamento normale.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>577</p>
<p>578</p></td>
<td style="border:1px solid black;"><p>Servizio privilegiato chiamato, operazione su un oggetto privilegiato</p></td>
<td style="border:1px solid black;"><p>Questi eventi con volumi elevati in genere non contengono informazioni sufficienti per comprendere l'accaduto o per consentire di prendere decisioni operative.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>594</p></td>
<td style="border:1px solid black;"><p>Handle di oggetto duplicato</p></td>
<td style="border:1px solid black;"><p>Comportamento normale.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>595</p></td>
<td style="border:1px solid black;"><p>Accesso indiretto a un oggetto</p></td>
<td style="border:1px solid black;"><p>Comportamento normale.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>596</p></td>
<td style="border:1px solid black;"><p>Backup della chiave master della protezione dati</p></td>
<td style="border:1px solid black;"><p>Con le impostazioni predefinite, questo evento si verifica automaticamente ogni 90 giorni.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>597</p></td>
<td style="border:1px solid black;"><p>Ripristino della chiave master della protezione dati</p></td>
<td style="border:1px solid black;"><p>Comportamento normale.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>624</p>
<p>642</p></td>
<td style="border:1px solid black;"><p>Evento 624 in cui il valore del campo <strong>Utente</strong> è <em>System</em>, seguito dall'evento 642 in cui il valore del campo <strong>Nome account di destinazione</strong> è <em>IUSR_machinename</em> o <em>IWAM_machinename</em> e il valore del campo <strong>Nome utente chiamante</strong> è <em>machinename$</em>.</p></td>
<td style="border:1px solid black;"><p>Questa sequenza di eventi indica che un amministratore ha installato IIS nel computer.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>624</p>
<p>630</p>
<p>642</p></td>
<td style="border:1px solid black;"><p>Il valore del campo <strong>Utente</strong> è <em>System</em> e tutti e tre gli eventi hanno lo stesso timestamp e il valore del campo <strong>Nome nuovo account/Nome account di destinazione</strong> è <em>HelpAssistant</em> e il valore del campo <strong>Nome utente chiamante</strong> è <em>DCname$</em></p></td>
<td style="border:1px solid black;"><p>Questa sequenza di eventi viene generata quando un amministratore installa Active Directory in un computer su cui è in esecuzione Windows Server 2003.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>624 o</p>
<p>642</p></td>
<td style="border:1px solid black;"><p>Il valore del campo <strong>Utente</strong> è <em>ExchangeServername$</em> e il campo <strong>Nome account di destinazione</strong> contiene un identificatore univoco globale (GUID)</p></td>
<td style="border:1px solid black;"><p>Questo evento si verifica la prima volta che un server di Exchange viene portato in linea generando automaticamente le cassette postali di sistema.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>624</p></td>
<td style="border:1px solid black;"><p>Il campo <strong>Nome utente chiamante</strong> contiene un qualsiasi utente e il valore del campo <strong>Nome nuovo account</strong> è <em>machinename$</em></p></td>
<td style="border:1px solid black;"><p>Un utente del dominio ha creato o connesso un nuovo account del computer nel dominio. Questo evento è accettabile se gli utenti hanno la facoltà di aggiungere computer a un dominio. In caso contrario, è necessaria un'analisi approfondita.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>627</p></td>
<td style="border:1px solid black;"><p>Il valore del campo <strong>Utente</strong> è <strong>System</strong>, il valore del campo <strong>Nome account di destinazione</strong> è <strong>TsInternetUser</strong> e il valore del campo <strong>Nome utente chiamante</strong> è in genere <strong>DCname$</strong></p></td>
<td style="border:1px solid black;"><p>Si tratta di eventi normali in un computer su cui è in esecuzione Servizi terminal.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>672</p></td>
<td style="border:1px solid black;"><p>Richiesta di ticket Kerberos AS</p></td>
<td style="border:1px solid black;"><p>Se si ricevono eventi di accesso 528 e 540 da tutti i computer, è possibile che l'evento 672 non contenga alcuna informazione utile aggiuntiva, poiché registra semplicemente che è stato concesso un ticket Kerberos TGT. Affinché si verifichi un accesso, deve comunque esistere un ticket di servizio concesso (evento 673).</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>680</p></td>
<td style="border:1px solid black;"><p>Accesso account</p></td>
<td style="border:1px solid black;"><p>Se si ricevono eventi di accesso 528 e 540 da tutti i computer, è possibile che l'evento 680 non contenga alcuna informazione utile aggiuntiva, poiché registra semplicemente la convalida delle credenziali dell'account. Un ulteriore evento di accesso registra le informazioni relative all'accesso effettuato dall'utente.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>697</p></td>
<td style="border:1px solid black;"><p>Chiamata all'API di controllo criterio password</p></td>
<td style="border:1px solid black;"><p>Comportamento normale.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>768</p></td>
<td style="border:1px solid black;"><p>Conflitto di spazio dei nomi nell'insieme di strutture</p></td>
<td style="border:1px solid black;"><p>Evento non relativo alla protezione.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>769</p>
<p>770</p>
<p>771</p></td>
<td style="border:1px solid black;"><p>Aggiunta, eliminazione o modifica delle informazioni sull'insieme di strutture trusted</p></td>
<td style="border:1px solid black;"><p>Questi eventi indicano un normale funzionamento dei trust tra insiemi di strutture. Non confondere questi eventi con l'aggiunta, l'eliminazione o la modifica del trust stesso.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Da 832 a 841</p></td>
<td style="border:1px solid black;"><p>Problemi vari relativi alla replica di Active Directory</p></td>
<td style="border:1px solid black;"><p>Nessuna implicazione sulla protezione.</p></td>
</tr>
</tbody>
</table>
  
##### Download
  
[![](images/Dd536262.icon_exe(it-it,TechNet.10).gif)Guida alla pianificazione del monitoraggio della protezione e della rilevazione degli attacchi](http://go.microsoft.com/fwlink/?linkid=41310)
  
[](#mainsection)[Inizio pagina](#mainsection)
