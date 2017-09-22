---
TOCTitle: Riepilogo dei certificati e delle licenze RMS
Title: Riepilogo dei certificati e delle licenze RMS
ms:assetid: '637ccfca-318e-4346-85b5-0945b058fb9c'
ms:contentKeyID: 18824624
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747595(v=WS.10)'
---

Riepilogo dei certificati e delle licenze RMS
=============================================

La tabella che segue elenca i certificati e le licenze utilizzate da RMS. Questi vengono illustrati dettagliatamente nei rimanenti argomenti della sezione.

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
<th>Certificato o licenza</th>
<th>Scopo</th>
<th>Contenuto</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Certificati concessori di licenze server</p></td>
<td style="border:1px solid black;"><p>Il certificato concessore di licenze server rilasciato ai server licenze assegna il diritto di rilasciare:</p>
<ul>  
<li>Licenze di pubblicazione<br />  
<br />  
</li>  
<li>Licenze d'uso<br />  
<br />  
</li>  
<li>Certificati concessori di licenze client<br />  
<br />  
</li>  
<li>Modelli di criteri per i diritti<br />  
<br />  
</li>  
</ul>  
<p>Il certificato concessore di licenze server rilasciato al cluster di certificazione principale assegna il diritto di rilasciare:</p>  
<ul>  
<li>Certificati per account con diritti ai client<br />  
<br />  
</li>  
<li>Certificati concessori di licenze server ai server licenze<br />  
<br />  
</li>
</ul></td>
<td style="border:1px solid black;"><p>Il certificato concessore di licenze server rilasciato a un server licenze contiene la chiave pubblica del server licenze.</p>
<p>Il certificato concessore di licenze server rilasciato al server di certificazione principale contiene la chiave pubblica del server di certificazione principale.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Certificati concessori di licenze client</p></td>
<td style="border:1px solid black;"><p>Concedono all'utente i diritti necessari per pubblicare contenuto protetto con RMS senza essere connessi alla rete aziendale.</p></td>
<td style="border:1px solid black;"><p>Contengono la chiave pubblica del certificato e la chiave privata del certificato crittografata con la chiave pubblica dell'utente che ha richiesto il certificato. Inoltre, contengono la chiave pubblica del server che ha rilasciato il certificato.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Certificati computer RMS</p></td>
<td style="border:1px solid black;"><p>Identificano un computer o un dispositivo considerato attendibile dal sistema RMS.</p></td>
<td style="border:1px solid black;"><p>Contengono la chiave pubblica del computer attivato. La chiave privata corrispondente è contenuta nell'archivio protetto del computer.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Certificati per account con diritti</p></td>
<td style="border:1px solid black;"><p>Identificano un utente nel contesto di un computer o una periferica specifica.</p></td>
<td style="border:1px solid black;"><p>Contengono la chiave pubblica dell'utente e la chiave privata dell'utente crittografata con la chiave pubblica del computer attivato.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Licenze di pubblicazione</p></td>
<td style="border:1px solid black;"><p>Specificano i diritti validi per il contenuto protetto con RMS.</p></td>
<td style="border:1px solid black;"><p>Contengono la chiave del contenuto simmetrica per la decrittrografazione del contenuto, il quale viene crittografato mediate la chiave pubblica del server che ha emesso la licenza.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Licenze d'uso</p></td>
<td style="border:1px solid black;"><p>Specificano i diritti validi per il contenuto protetto con RMS nel contesto di uno specifico utente autenticato.</p></td>
<td style="border:1px solid black;"><p>Contengono la chiave simmetrica per la decrittografia del contenuto, crittografata con  la chiave pubblica dell'utente.</p></td>
</tr>  
</tbody>  
</table>
