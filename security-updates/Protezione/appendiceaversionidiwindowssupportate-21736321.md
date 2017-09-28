---
TOCTitle: 'Appendice A: Versioni di Windows supportate'
Title: 'Appendice A: Versioni di Windows supportate'
ms:assetid: '792a6efa-3232-4fb8-a233-523f9103aae7'
ms:contentKeyID: 21736321
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Dd920329(v=TechNet.10)'
---

Appendice A: Versioni di Windows supportate
===========================================

Pubblicato: 11 ottobre 2004 | Aggiornato: 24/11/2004

### Introduzione

La tabella inclusa in questa appendice mostra lo stato delle diverse versioni del sistema operativo Microsoft® Windows® di client e server. La tabella illustra il ruolo del sistema nella soluzione *Protezione delle reti LAN senza fili con Servizi certificati*, le versioni del sistema operativo utilizzabili in tale ruolo, nonché indica se il sistema operativo è supportato o meno. L'ultima colonna della tabella contiene avvisi o note aggiuntive.

Le informazioni sul supporto di ciascun ruolo del server sono classificate come riportato di seguito:

-   **Supportato e testato** - La versione del sistema operativo è stata usata nel laboratorio MSS (Microsoft Solutions for Security) per la creazione della soluzione ed è stata testata con la soluzione.

-   **Supportato** - La versione del sistema operativo non è stata testata con la soluzione, ma Microsoft supporta il suo uso in questo ruolo. Oltre a seguire le istruzioni incluse in questa soluzione, può essere necessaria una configurazione o una personalizzazione supplementare.

-   **Non supportato** - La versione del sistema operativo non funziona nella soluzione così descritta. Potrebbe essere possibile configurare il sistema non supportato in modo che funzioni correttamente, ma questo richiederebbe molto lavoro.

-   **Sconosciuto** - La versione del sistema operativo potrebbe funzionare in questo ruolo, in quanto non sussistono controindicazioni di natura tecnica, ma è necessario eseguire verifiche e test.

Se la versione di un sistema operativo non è visualizzata accanto al ruolo, significa che non funziona (**Non supportato**) oppure non si sa se funziona (**Sconosciuto**).

**Tavola A.1. Supporto delle versioni del sistema operativo nella soluzione**

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
<th><p>Ruolo</p></th>
<th><p>Versione del sistema operativo</p></th>
<th><p>Status</p></th>
<th><p>Note</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Client senza fili</p></td>
<td style="border:1px solid black;"><p>- Windows XP Professional</p>
<p>- Windows XP Professional Tablet Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Microsoft Windows 2000</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p>Necessario procurarsi il client 802.1X da Microsoft.com.</p>
<p>I certificati utente sono distribuiti manualmente o tramite script.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>- Microsoft Windows NT® versione 4.0</p>
<p>- Windows 9<em>x</em></p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p>È necessario procurarsi il client 802.1X tramite Premier Support.</p>
<p>I certificati sono distribuiti manualmente o tramite script.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Altre piattaforme</p></td>
<td style="border:1px solid black;"><p>Sconosciuto</p></td>
<td style="border:1px solid black;"><p>I client devono supportare 802.1X e il protocollo EAP-TLS (Extensible Authentication Protocol-Transport Layer Security).</p>
<p>I certificati sono distribuiti manualmente o tramite script.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Autorità di certificazione (CA) principale</p></td>
<td style="border:1px solid black;"><p>Microsoft Windows Server™ 2003, Standard Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>- Windows Server 2003, Enterprise Edition</p>
<p>- Windows 2000 Server</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Autorità di certificazione di terze parti</p></td>
<td style="border:1px solid black;"><p>Sconosciuto</p></td>
<td style="border:1px solid black;"><p>Deve supportare la revoca.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>CA di emissione</p></td>
<td style="border:1px solid black;"><p>Windows Server 2003, Enterprise Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>- Altre versioni Windows Server</p>
<p>- Autorità di certificazione di terze parti</p></td>
<td style="border:1px solid black;"><p>Non supportate</p></td>
<td style="border:1px solid black;"><p>Possono essere generati certificati utilizzabili.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Server RADIUS</p></td>
<td style="border:1px solid black;"><p>Windows Server 2003, Standard Edition o Enterprise Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p>L'edizione Standard supporta non più di 50 punti di accesso.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Windows 2000 Server</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p>Il Servizio autenticazione Internet (IAS) di Windows 2000 può essere utilizzato per 802.1X senza fili con la perdita di alcune funzionalità.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Altre piattaforme</p></td>
<td style="border:1px solid black;"><p>Non supportate</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Controller di dominio</p></td>
<td style="border:1px solid black;"><p>Windows Server 2003, Standard Edition o Enterprise Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p>Il servizio directory Active Directory® deve disporre di uno schema Windows 2003 e un dominio nella modalità nativa Windows 2000 o versioni successive.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Windows 2000 Server</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p>Active Directory® deve disporre di uno schema Windows 2003 e un dominio nella modalità nativa Windows 2000 o versioni successive.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Server Web</p></td>
<td style="border:1px solid black;"><p>Internet Information Service (IIS): Windows Server 2003</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>IIS: Windows 2000</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Altre piattaforme</p></td>
<td style="border:1px solid black;"><p>Non supportate</p></td>
<td style="border:1px solid black;"><p>La maggior parte dei server Web funzionano con la pubblicazione di certificati CA ed elenchi di revoche di certificati (CRL). È necessario il supporto delle pagine ASP (Active Server Pages) per le pagine di registrazione CA.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Server infrastruttura, quali DNS (Domain Name System) e DHCP (Dynamic Host Configuration Protocol)</p></td>
<td style="border:1px solid black;"><p>Windows Server 2003, Standard Edition o Enterprise Edition</p></td>
<td style="border:1px solid black;"><p>Supportato e testato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Windows 2000 Server</p></td>
<td style="border:1px solid black;"><p>Supportato</p></td>
<td style="border:1px solid black;"><p> </p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p> </p></td>
<td style="border:1px solid black;"><p>Altre piattaforme</p></td>
<td style="border:1px solid black;"><p>Sconosciuto</p></td>
<td style="border:1px solid black;"><p>DNS, le soluzioni di gestione e DHCP di terze parti dovrebbero funzionare con questa soluzione, purché siano soddisfatti i requisiti di base per i client Windows e Active Directory.</p></td>
</tr>
</tbody>
</table>
  
[](#mainsection)[Inizio pagina](#mainsection)
