---
TOCTitle: Definizioni delle chiavi RMS
Title: Definizioni delle chiavi RMS
ms:assetid: 'b052305c-1db7-434a-bad9-26d704156776'
ms:contentKeyID: 18824746
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747729(v=WS.10)'
---

Definizioni delle chiavi RMS
============================

La tabella che segue elenca le chiavi utilizzate in un sistema RMS.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Chiave</th>
<th>Utilizzo</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Chiavi del server</p></td>
<td style="border:1px solid black;"><p><strong>Chiave pubblica</strong></p>
<p>Crittografa la chiave del contenuto presente in una licenza di pubblicazione affinché solo il server RMS possa richiamare la chiave del contenuto ed emettere le licenze d'uso in base a tale licenza di pubblicazione.</p>  
<p><strong>Chiave privata</strong></p>
<p>Firma tutti i certificati e le licenze rilasciati dal server.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Chiavi del computer</p></td>
<td style="border:1px solid black;"><p><strong>Chiave pubblica</strong></p>
<p>Crittografa la chiave privata di un certificato per account con diritti.</p>  
<p><strong>Chiave privata</strong></p>
<p>Decrittografa un certificato per account con diritti.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Chiavi del concessore di licenze client</p></td>
<td style="border:1px solid black;"><p><strong>Chiave pubblica</strong></p>
<p>Crittografa la chiave simmetrica del contenuto nelle licenze di pubblicazione che rilascia.</p>  
<p><strong>Chiave privata</strong></p>
<p>Firma le licenze di pubblicazione rilasciate localmente mentre l'utente non è connesso alla rete.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Chiavi dell'utente</p></td>
<td style="border:1px solid black;"><p><strong>Chiave pubblica</strong></p>
<p>Crittografa la chiave del contenuto presente in una licenza d'uso affinché solo un determinato utente possa utilizzare il contenuto protetto con RMS mediante tale licenza.</p>  
<p><strong>Chiave privata</strong></p>
<p>Consente all'utente di utilizzare il contenuto protetto con RMS.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Chiavi del contenuto</p></td>
<td style="border:1px solid black;"><p>Crittografa il contenuto protetto con RMS nel momento in cui l'autore lo pubblica.</p></td>
</tr>  
</tbody>  
</table>
