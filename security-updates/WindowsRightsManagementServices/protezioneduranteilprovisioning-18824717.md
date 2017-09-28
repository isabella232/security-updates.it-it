---
TOCTitle: Protezione durante il provisioning
Title: Protezione durante il provisioning
ms:assetid: '9f1282c5-5642-4870-a9a4-c3a485f8ff76'
ms:contentKeyID: 18824717
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747616(v=WS.10)'
---

Protezione durante il provisioning
==================================

È possibile utilizzare il sito Web Amministrazione di RMS per eseguire il provisioning delle risorse RMS in un sito Web esistente. Durante il provisioning, nel sito Web vengono creati directory virtuali e pool di applicazioni, mentre sul server database vengono creati e configurati database RMS. Facoltativamente, se è connesso a Internet, il server può essere registrato con il Servizio di Enrollment Microsoft durante il processo di provisioning.

In questa fase, RMS utilizza gli account illustrati nella seguente tabella.

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
<th>Account</th>
<th>Scopo</th>
<th>Autorizzazioni</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Account dell'utente connesso</p></td>
<td style="border:1px solid black;"><p>Crea directory virtuali e pool di applicazioni. IIS richiede l'autenticazione di Windows, mentre RMS rappresenta l'utente connesso che deve essere connesso localmente.</p></td>
<td style="border:1px solid black;"><p>Controllo completo (l'utente connesso deve essere un amministratore locale).</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Account di sistema</p></td>
<td style="border:1px solid black;"><p>Crea l'assembly temporaneo per la serializzazione.</p></td>
<td style="border:1px solid black;"><p>Autorizzazioni di lettura e scrittura per la cartella temporanea di Windows, C:\Windows\Temp.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Account di ASPNET</p></td>
<td style="border:1px solid black;"><p>Crea l'assembly temporaneo dei file *.aspx.</p></td>
<td style="border:1px solid black;"><p>Accesso alla directory della cache dell'assembly temporaneo, per impostazione predefinita C:\Windows\Microsoft.NET\Framework\v1.1.4322\Temporary ASP.NET Files.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Account Servizio di rete</p></td>
<td style="border:1px solid black;"><p>Registra il punto di connessione del servizio in Active Directory.</p></td>
<td style="border:1px solid black;"><ul>
<li>Autorizzazioni di sola lettura per il sito del provisioning (in genere C:\Inetpub\Wwwroot\Provisioning).<br />
<br />
</li>
<li>Autorizzazioni in lettura e scrittura per la chiave del Registro di sistema <strong>DRMS</strong>. Le autorizzazioni vengono concesse dal programma di installazione di RMS, il quale crea anche la chiave del Registro di sistema che segue.<br />
<br />
Su computer in cui è in esecuzione la versione a 32 bit di Windows Server 2003:<br />
<br />
<code>HKEY_LOCAL_MACHINE\Software\Microsoft\DRMS\1.0</code><br />
<br />
Su computer in cui è in esecuzione la versione a 64 bit di Windows Server 2003:<br />
<br />
<code>HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\DRMS\1.0</code><br />
<br />
</li>
</ul></td>
</tr>
</tbody>
</table>
<p> </p>

Durante il provisioning, RMS esegue le seguenti operazioni:

-   Sul server database:
    -   Crea i database di configurazione, dei servizi di directory e di registrazione attività.
    -   Assegna le autorizzazioni di accesso al gruppo del servizio RMS.
    -   Installa le stored procedure nei database e assegna le autorizzazioni di esecuzione al gruppo del servizio RMS.
    -   Esegue query sul database master.
-   Aggiunge il gruppo del servizio RMS al gruppo IIS\_WPG.
-   In C:\\Inetpub\\Wwwroot\\\_wmcs, crea una gerarchia di directory virtuali, file e pool di applicazioni per i servizi Web e il sito Web Amministrazione.
-   Imposta elenchi DACL per directory virtuali, file e pool di applicazioni.
-   Concede al gruppo del servizio RMS l'accesso alla cartella temporanea.
-   Quando l'utente specifica la protezione della chiave software, crittografa la chiave privata del concessore di licenze server prima di memorizzarla nel database. Durante il provisioning, RMS richiede una password e ottiene l'accesso alla DPAPI a livello di computer.
-   Installa il servizio listener per la registrazione attività.
-   Crea una coda di messaggi per la registrazione attività.
-   Se il provisioning riguarda il server di certificazione principale, imposta il punto di connessione del servizio in Active Directory.
