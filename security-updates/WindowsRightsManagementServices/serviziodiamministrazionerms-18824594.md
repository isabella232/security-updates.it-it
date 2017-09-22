---
TOCTitle: Servizio di amministrazione RMS
Title: Servizio di amministrazione RMS
ms:assetid: '4bd3e142-f0f6-40e9-a160-deab28ce5b88'
ms:contentKeyID: 18824594
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747560(v=WS.10)'
---

Servizio di amministrazione RMS
===============================

Il servizio di amministrazione viene eseguito sul cluster principale di RMS e sugli eventuali cluster licenze. Nel servizio di amministrazione è ospitato il sito Web Amministrazione; inoltre, il servizio consente di gestire RMS.

Il file applicazione del servizio di amministrazione, Default.aspx, si trova nella directory virtuale Admin, *Sito\_Web\_RMS*\\\_wmcs\\Admin, dove *Sito\_Web\_RMS* viene sostituito dal nome del sito Web su cui è stato eseguito il provisioning di RMS.

L'elenco di controllo di accesso predefinito su questo servizio è illustrato nella seguente tabella:

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Utente o gruppo</th>
<th>Autorizzazione predefinita</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Administrators</p></td>
<td style="border:1px solid black;"><p>Controllo completo</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Gruppo di servizi RMS</p></td>
<td style="border:1px solid black;"><p>Lettura e Esecuzione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>SISTEMA</p></td>
<td style="border:1px solid black;"><p>Controllo completo</p></td>
</tr>  
</tbody>  
</table>
