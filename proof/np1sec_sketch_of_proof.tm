<TeXmacs|1.99.2>

<style|generic>

<\body>
  <doc-data|<doc-title|Sketch of Security Proof for (n+1)Sec Protocol>>

  The (n+1)Sec protocol is composed of following sub protocol:

  <\enumerate>
    1. <strong|TDH>: Triple DH deniable Authentication

    2. <strong|FAGKE>: Flexible Authenticated Group Key Exchange protocol
    presented in <cite|AMP10>

    3. <strong|SecCom>: Secure (authenticated confidential) Send and Receive.

    4. <strong|TCA>: Transcript Consistency Assurance.
  </enumerate>

  The threat model for each of these protocol is described in Section VI. The
  security of FAGKE is proven in the presented threat model. The SecComm
  consists of convential ``sign'' and ``encrypt'' functions and its security
  has been studied as a subprotocol to various protocols. We are not aware of
  any existing proof for TDH and TCA subprotocol.

  The sketch of the proof goes as follows, in Section
  <reference|sect-tdh-sec> and Section <reference|sect-tca-sec> we give
  convential formal proof of the security properties of TDH and TCA
  respectively. In Section <reference|sect-np1sec-pclize> we reforumlates the
  proves of all four protocols in Protocol Composition Logic (PCL). In
  Section <reference|sect-comp-sec>, we proof the security of (n+1)sec by
  proving the relative security of above sub prorotocol in relation to each
  other:

  <\enumerate>
    <item><math|Q<rsub|1>> as Parallel composition of TDH and FAGKE.

    <item>Sequential composition of <math|Q<rsub|1>> and SecCom.

    <item> Parallel compostion of SecCom and TCA.
  </enumerate>

  <section|Security of Triple Deffie-Hellman Authentication>

  <label|sect-tdh-sec>

  <section|Security of Transcript Consistency Assurance>

  <label|sect-tca-sec>

  <section|(n+1)Sec components in PCL Langugae>

  <label|sect-np1sec-pclize>

  <section|Security of composed sub protocols>

  <label|sect-comp-sec>
</body>

<initial|<\collection>
</collection>>

<\references>
  <\collection>
    <associate|auto-1|<tuple|1|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-2|<tuple|2|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-3|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-4|<tuple|4|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-comp-sec|<tuple|4|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-in-pcl|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-pclize|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-tca-sec|<tuple|2|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-tdh-sec|<tuple|1|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
  </collection>
</references>

<\auxiliary>
  <\collection>
    <\associate|bib>
      AMP10
    </associate>
  </collection>
</auxiliary>