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

  <section|Security of Triple Diffie-Hellman Authentication>

  <subsection|The Triple Diffie-Hellman Protocol>

  <\float|float|tbh>
    <big-table|<tabular|<tformat|<table|<row|<cell|Round
    1>|<cell|<math|A\<rightarrow\>B: <rprime|''>A<rprime|''>,g<rsup|a>>>|<cell|<math|B\<rightarrow\>A:<rprime|''>B<rprime|''>,g<rsup|b>>>>|<row|<cell|Key
    Computation>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|b>|)><rsup|A>\|<around*|(|g<rsup|B>|)><rsup|a>\|<around*|(|g<rsup|b>|)><rsup|a>|)>>>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|A>|)><rsup|b>\|<around*|(|g<rsup|a>|)><rsup|B>\|<around*|(|g<rsup|a>|)><rsup|b>|)>>>>|<row|<cell|Round
    2>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,A|)>|)>>>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,B|)>|)>>>>>>>|>
  </float>Assuming that <math|A> and <math|B> are represeneted by long term
  public key <math|g<rsup|A>> and <math|g<rsup|B>> respectively:

  <subsection|The deniablity of TDH>

  <label|sect-tdh-sec> We will prove a parallel to Theorem 4 <cite|GKR06>
  which proves the deniability of SKEME. We use the notation which are
  introduced in Section <reference|sect-deniabl-adv>. Following the same
  notation:

  <\definition>
    By <math|Adv<rsub|deny><rsup|\<ast\>>> we represent the party which
    represent the interaction of the Simulator <math|Sim> with the adverasy.
    In other word, <math|Adv<rsup|\<ast\>><rsub|deny>> has access to all
    information which <math|Adv<rsub|deny>> possess.
  </definition>

  <\theorem>
    If Computational Diffie-Hellman (CDH) is interactable then Triple DH
    Algorithm is deniable.
  </theorem>

  <\proof>
    We build <math|Sim<rsub|>> which interacts with <math|Adv<rsub|deny>>. We
    show that if <math|\<cal-J\>> is able to distinguish
    <math|Trans<rsub|Sim>> from <math|Trans<rsub|Real>>, ze should be able to
    solve CDH as well.

    Intuitively, when <math|Adv<rsub|deny>> sends <math|g<rsup|a>> to
    <math|<with|math-font|cal|>Sim<rsub|>>, <math|Sim> <math|Adv<rsub|deny>>
    for <math|a>, in this way <math|Sim> also can compute the same key
    <math|k> by asking <math|Adv<rsub|deny><rsup|\<ast\>>>. If
    <math|Adv<rsub|deny>> has chosen <math|g<rsup|a>\<in\>Tr<around*|(|B|)>>,
    then <math|Sim> will choose a random value from the same key space. Then
    compute the confirmation value using <math|k>.
  </proof>

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
    <associate|auto-1|<tuple|1|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-2|<tuple|1.1|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-3|<tuple|1|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-4|<tuple|1.2|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-5|<tuple|2|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-6|<tuple|3|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|auto-7|<tuple|4|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-comp-sec|<tuple|4|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-in-pcl|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-pclize|<tuple|3|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-tca-sec|<tuple|2|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-tdh-sec|<tuple|1.2|?|../../../../.TeXmacs/texts/scratch/no_name_12.tm>>
  </collection>
</references>

<\auxiliary>
  <\collection>
    <\associate|bib>
      AMP10

      GKR06
    </associate>
    <\associate|toc>
      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|1<space|2spc>Security
      of Triple Diffie-Hellman Authentication>
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-1><vspace|0.5fn>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|2<space|2spc>Security
      of Transcript Consistency Assurance>
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-2><vspace|0.5fn>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|3<space|2spc>(n+1)Sec
      components in PCL Langugae> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-3><vspace|0.5fn>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|4<space|2spc>Security
      of composed sub protocols> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-4><vspace|0.5fn>
    </associate>
  </collection>
</auxiliary>