---
TOCTitle: Modifica delle impostazioni del Registro di sistema per il pool di connessioni
Title: Modifica delle impostazioni del Registro di sistema per il pool di connessioni
ms:assetid: 'c61d91db-a1ad-4ca5-a492-015da629afbc'
ms:contentKeyID: 18824762
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747660(v=WS.10)'
---

Modifica delle impostazioni del Registro di sistema per il pool di connessioni
==============================================================================

Per migliorare le prestazioni del sistema, è possibile utilizzare le voci delle chiavi del Registro di sistema per impostare le proprietà del pool di connessioni LDAP (Lightweight Directory Access Protocol) di Active Directory utilizzato da RMS.

Sui computer che eseguono la versione a 32 bit di Windows Server 2003, la seguente chiave del registro di sistema rappresenta il percorso completo della sottochiave delle voci del registro per il pool di connessioni:

**HKEY\_LOCAL\_MACHINE\\Software\\Microsoft\\DRMS\\1.0**

Sui computer che eseguono la versione a 64 bit di Windows Server 2003, la seguente chiave del registro di sistema rappresenta il percorso completo della sottochiave delle voci del registro per il pool di connessioni:

**HKEY\_LOCAL\_MACHINE\\SoftwareWOW6432Node\\Microsoft\\DRMS\\1.0**

Nella tabella seguente, sono elencate le voci che è possibile aggiungere per sovrascrivere le impostazioni del pool di connessioni di Active Directory predefinite. I valori visualizzati sono quelli predefiniti. Per ulteriori informazioni sulle modalità di creazione di un elenco di query in RMS e sull'utilizzo di tali impostazioni, vedere “Ottimizzazione delle impostazioni del pool di connessioni di Active Directory”, più indietro in questo argomento.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="20%" />
<col width="20%" />
<col width="20%" />
<col width="20%" />
<col width="20%" />
</colgroup>
<thead>
<tr class="header">
<th>Nome</th>
<th>Tipo</th>
<th>Valore predefinito</th>
<th>Descrizione</th>
<th>Note</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>GC</p></td>
<td style="border:1px solid black;"><p>String</p></td>
<td style="border:1px solid black;"><p>name-1, ..., name-n</p></td>
<td style="border:1px solid black;"><p>Elenco separato da virgole di cataloghi globali (tramite l'utilizzo di nomi DNS). Tramite questa chiave, è possibile imporre in RMS il solo utilizzo dei cataloghi globali specificati.</p></td>
<td style="border:1px solid black;"><p>Se non si desidera che tramite RMS venga creato un elenco di query, utilizzare questa impostazione per specificare i cataloghi globali da utilizzare.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>MinGC</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>1</p></td>
<td style="border:1px solid black;"><p>Numero minimo di cataloghi globali che devono essere disponibili prima che RMS possa essere avviato.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>MaxGC</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>15</p></td>
<td style="border:1px solid black;"><p>Numero massimo di cataloghi globali che verranno aggiunti all'elenco di query tramite l'algoritmo di rilevamento della topologia.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>ThreshHoldAlive</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>1</p></td>
<td style="border:1px solid black;"><p>Numero minimo di connessioni da cui deve essere inviata una risposta prima che tramite i servizi di rilevamento venga avviata la ricerca dei cataloghi globali da aggiungere all'elenco di query affinché in RMS vengano accettate le richieste.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>RetryDown</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>5</p></td>
<td style="border:1px solid black;"><p>Numero di volte in cui viene effettuato un nuovo tentativo con una connessione inattiva prima che venga dichiarato che tale connessione non risponde.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>TimeRetryDown</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>300</p></td>
<td style="border:1px solid black;"><p>Numero di secondi da attendere prima di effettuare un nuovo tentativo con una connessione inattiva.</p></td>
<td style="border:1px solid black;"><p>Non è necessario modificare questa impostazione predefinita se non in casi eccezionali.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>TimeRetrySlow</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>30</p></td>
<td style="border:1px solid black;"><p>Numero di secondi da attendere prima di effettuare un nuovo tentativo con una connessione lenta.</p></td>
<td style="border:1px solid black;"><p>Non è necessario modificare questa impostazione predefinita se non in casi eccezionali.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>WtRoundRobin</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>1</p></td>
<td style="border:1px solid black;"><p>Peso del round robin durante il bilanciamento del carico.</p></td>
<td style="border:1px solid black;"><p>Importanza relativa del round robin nel bilanciamento del carico. 1 è il valore minimo.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>WtThreadCount</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>100</p></td>
<td style="border:1px solid black;"><p>Peso del conteggio dei thread per connessione durante il bilanciamento del carico.</p></td>
<td style="border:1px solid black;"><p>Importanza relativa di un bilanciamento dei thread basso.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>WtSlow</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>1,000</p></td>
<td style="border:1px solid black;"><p>Peso della connessione lenta durante il bilanciamento del carico.</p></td>
<td style="border:1px solid black;"><p>Importanza relativa della mancata lentezza della connessione.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>TimeOutForGC</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>5</p></td>
<td style="border:1px solid black;"><p>Numero di secondi da attendere prima del timeout di una richiesta di aggiunta di un catalogo globale all'elenco di query.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>LdapTimeOut</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>5</p></td>
<td style="border:1px solid black;"><p>Numero di secondi da attendere prima del timeout durante l'esecuzione di API LDAP.</p></td>
<td style="border:1px solid black;"></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>TopDownExpansionLDAPTimeOut</p></td>
<td style="border:1px solid black;"><p>DWORD</p></td>
<td style="border:1px solid black;"><p>40</p></td>
<td style="border:1px solid black;"><p>Numero di secondi da attendere prima del timeout durante l'esecuzione di query LDAP con espansione dall'alto verso il basso.</p></td>
<td style="border:1px solid black;"></td>
</tr>
</tbody>
</table>
  
| ![](images/Cc747660.Caution(WS.10).gif)Attenzione                                                                                                                                          |  
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| Apportando modifiche errate al Registro di sistema, è possibile danneggiare seriamente il sistema. Prima di apportare modifiche al Registro di sistema, effettuare il backup dei dati importanti presenti nel computer. |
