<TeXmacs|1.0.7.15>

<\body>
  <doc-data|<doc-title|Sketch of Security Proof for (n+1)Sec Protocol>>

  The (n+1)Sec protocol is composed of following subprotocols:

  <\enumerate>
    1. <strong|TDH>: Triple DH deniable Authentication

    2. <strong|FAGKE>: Flexible Authenticated Group Key Exchange protocol
    presented in <cite|AMP10>

    3. <strong|SecCom>: Secure (authenticated confidential) Send and Receive.

    4. <strong|TCA>: Transcript Consistency Assurance.
  </enumerate>

  The threat model for each of these protocols is described in Section VI.  The
  security of FAGKE is proven in the presented threat model. The SecCom consists
  of conventional \Psign\Q and \Pencrypt\Q functions and its security has been
  studied as a subprotocol to various protocols. We are not aware of any
  existing proof for the TDH and TCA subprotocols.

  The sketch of the proof is structured as follows: Section <reference|sect-tdh>
  deals with security of TDH, namely its deniability. The authentication of TDH
  will be proven as a part of AKE security proof. We also prove the TDH protocol
  as a 2-party secure AKE in model presented in <cite|AMP10>. Section
  <reference|sect-GKE> proves the security properties of the group key exchange
  protocol. \ In Section <reference|sect-tca-sec> we give proof of the security
  properties of TCA.

  <section|General Definition>

  In this section we introduce the ideas and definition we are using throughout
  the proof.

  <\definition>
    <label|defn-cdh>Suppose <math|\<bbb-G\>> is a multiplicative group. Given
    arbitary <math|g,g<rsup|a>,g<rsup|b>\<in\>\<bbb-G\>>, the
    <strong|Computational Diffie-Hellman (CDH) problem> is to compute
    <math|g<rsup|a b>>.
  </definition>

  <\definition>
    <label|defn-ddh>Following the notation in Definition <reference|defn-cdh>,
    given arbitary <math|g,g<rsup|a>,g<rsup|b>,g<rsup|c>\<in\>\<bbb-G\>>, the
    <strong|Decisional Diffie-Hellman (DDH) problem> is to determine if
    <math|g<rsup|c>=g<rsup|a b>>.
  </definition>

  <\definition>
    <label|defn-gdh-assumption>Following the notation in Definition
    <reference|defn-ddh>, <strong|Gap Diffie-Hellman problem> is to compute
    <math|g<rsup|a b>> while having access to \ a DDH oracle. In other words,
    <strong|GDH assumption> \ for group <math|\<bbb-G\>> asserts that even if
    DDH is easy in <math|\<bbb-G\>>, computing <math|g<rsup|a b>> is hard.
  </definition>

  <\definition>
    <label|defn-gdh-solver>A <strong|Gap Diffie-Hellman Solver> or a <strong|GDH
    solver> <math|\<cal-S\>> for group <math|\<bbb-G\>> is a function
    <math|\<cal-S\>> defined as

    <\equation*>
      \<cal-S\>:<around*|(|g,g<rsup|a>,g<rsup|b>,\<cal-O\><rsub|DDH><rsub|>|)>\<longmapsto\>g<rsup|a
      b>
    </equation*>

    Where <math|\<cal-O\><rsub|DDH>> is a DDH oracle for group
    <math|\<bbb-G\>.>
  </definition>

  <\definition>
    We indicate <strong|the set of all possible participants> (in the universe)
    by <math|\<cal-U\>>, such that <math|<around*|\||\<cal-U\>|\|>> = <math|N>,
    where each participant is represented by a unique identity <math|U<rsub|i>>.
    Each <math|U<rsub|i>> is verifiably identified by a long-term public key
    <math|LPK<rsub|i>> for which it possesses its corresponding long-term
    private key <math|LSK<rsub|i>>.
  </definition>

  In modelling the chat session, in terms of the adversarial models and protocol
  specifications, the notation of <cite|ACMP10> is followed. This notation is
  common to other publications on group key exchange such as <cite|GBNM11>,
  and is adhered to for consistency.

  <\definition>
    We indicate <strong|the set of all possible participants> (in the universe)
    by <math|\<cal-U\>>, such that <math|<around*|\||\<cal-U\>|\|>> = <math|N>.
    Each participant is represented by a unique identity <math|U<rsub|i>>. Each
    <math|U<rsub|i>> is verifiably identified by a long-term public key
    <math|LPK<rsub|i>> for which it possesses its corresponding long-term
    private key <math|LSK<rsub|i>>.
  </definition>

  <\definition>
    A <strong|multi-party chat session> is an ordered pair
    <math|\<cal-S\>\<assign\><around*|(|S\<nocomma\>\<nocomma\>,sid<rsup|\<cal-S\>>|)>>,
    in which <math|S\<subseteq\>\<cal-U\>> and <math|sid> is the unique session
    id computed as a function of the participants' id and their ephemeral keys.
    The <strong|Ephemeral key> of participant <math|U<rsub|i>> is the private
    and public key pair of
    <math|<around*|(|x<rsub|i><rsup|S>,y<rsub|i><rsup|S>|)>> that is generated
    by a participant for the purpose of participating in <math|\<cal-S\>> such
    that

    <\equation*>
      y<rsup|S><rsub|i>= x<rsub|i><rsup|S>g
    </equation*>

    in additive notation, where <math|g> is the generator of a group <math|G>
    with hard Discrete Logarithm Problem (DLP). We refer to either of
    <math|x<rsub|i>> or <math|y<rsub|i>> as the ephemeral key of user
    <math|U<rsub|i>> when there is chance of ambiguity. Without loss of
    generality we assume:

    <\equation*>
      S\<assign\><around*|{|U<rsub|1>,\<ldots\>,U<rsub|n>|}>
    </equation*>

    The ordered <strong|list of participants> and ordered list of their
    ephemeral keys is defined as:

    <\equation*>
      plist<rsup|\<cal-S\>>:=<around*|(|U<rsub|1>,\<ldots\>,U<rsub|n>|)>
    </equation*>

    <\equation*>
      klist<rsup|\<cal-S\>>\<assign\><around*|(|y<rsub|1>,\<ldots\>,y<rsub|n>|)>
    </equation*>

    Accordingly, we denote the interviewing concatenation of these two lists
    as:

    <\equation*>
      plist<rsup|\<cal-S\>><around*|\||klist<rsup|\<cal-S\>>:=U<rsub|1>|\|>y<rsub|1><around*|\||U<rsub|2>|\|>y<rsub|2><around*|\||\<cdots\>|\|>U<rsub|n>\|y<rsub|n>
    </equation*>

    The order is to be uniquely computable by all participants
    (lexicographically ordered using the long-term public key of
    participants, for example).
  </definition>

  A subset of participants might want to start a session in which the remaining
  parties are excluded (for example when those parties leave the chatroom). The
  following definition formalizes such situation:

  <\definition>
    For a session <math|\<cal-S\>=<around*|(|S,sid<rsup|\<cal-S\>>|)>>,
    <math|\<cal-T\>=<around*|(|S,sid<rsub|\<cal-T\>>|)>> is called a
    <strong|sub-session> of <math|\<cal-S\>> if <math|T\<subset\>S> and all
    participants <math|U<rsub|i>\<in\>T> use the same ephemeral key for both
    <math|\<cal-S\>> and <math|\<cal-T\>>. In other words, the same ephemeral
    keys are used to compute <math|sid<rsub|\<cal-T\>>>. In such situation,
    we call <math|\<cal-S\>> the super-session of <math|\<cal-T\>>.
  </definition>

  <\definition>
    An <with|font-series|bold|authenticated group key exchange (AGKE)> is a
    protocol <math|\<Pi\>> each participant executes in order to communicate
    (by means of sending, receiving or computing) a cryptographic secret -
    namely a key - among the other parties of a session. By
    <math|\<Pi\><rsup|\<cal-S\>><rsub|i>> we refer to the <strong|instance of
    the protocol run by> <math|U<rsub|i>> for session <math|\<cal-S\>>. The
    <math|sid<rsup|\<cal-S\>>> computed by
    <math|\<Pi\><rsup|\<cal-S\>><rsub|i>> and denoted by
    <math|sid<rsup|\<cal-S\>><rsub|i>> (or <math|sid<rsub|i>> when there is
    no chance of confusion) is called the <strong|session id observed by>
    <math|U<rsub|i>>. Similarly, <math|plist<rsup|\<cal-S\>><rsub|i>> (or
    <math|plist<rsub|i>>) is the list of participants which <math|U<rsub|i>>
    believes are participating in the attack and
    <math|klist<rsup|\<cal-S\>><rsub|i> > (or <math|klist<rsub|i>>) is their
    perceived set of ephemeral public keys.
  </definition>

  <\definition>
    To communicate in a multi-party session, each participant
    <math|U<rsub|i>> needs to compute a symmetric <strong|session key>
    <math|sk<rsup|\<cal-S\>><rsub|i>> which should be computable by other
    parties participating in the chat or be transmitted confidentially to
    them. We say a participant enters the <with|font-series|bold|accepted
    state> if they have computed <math|sk<rsub|i><rsup|\<cal-S\>>> and have
    detected no error in the protocol.
  </definition>

  The essential defining factor is that part of
  <math|sk<rsup|\<cal-S\>><rsub|i>> should become common knowledge for the
  session participants at the end of AGKE execution, so they can communicate
  confidentially. Nevertheless, it is not necessary that all participants
  share the same secret <math|sk<rsup|\<cal-S\>><rsub|i>> among themselves
  and they can broadcast their messages encrypted using multiple keys. This
  decreases the efficiency as well as complicates the security analysis of
  the protocol. As such, we assume that at the end of running a correct AGKE,
  all participants possess a shared secret:

  <\definition>
    Two accepted instances <math|\<Pi\><rsub|i><rsup|\<cal-S\>>> and
    <math|\<Pi\><rsup|\<cal-S\>><rsub|j>> are considered <strong|partnered>
    if <math|sid<rsub|i>=sid<rsub|j>> and <math|plist<rsub|i>=plist<rsub|j>>.
  </definition>

  <\definition>
    A <with|font-series|bold|correct> AKGE algorithm is an AKGE where, when
    all <math|\<Pi\><rsup|\<cal-S\>><rsub|i>> instances of AKE algorithm are
    initiated with access to a network which correctly forwards all messages
    without modification, all participants ultimately are partnered and all
    compute equal <math|sk<rsup|\<cal-S\>><rsub|i>>'s.
  </definition>

  After all instances of a session have partnered, they need to use the computed
  common symmetric key to communicate securely. Following the subprotocol can
  guarantee some of the security properties which <math|<around*|(|n+1|)>sec>
  aims to promise.

  <\definition>
    <label|defn-AEAD><dueto|<cite|BHMS15> Definition 3.1><strong|A
    <em|stateful authenticated encryption with associated data> (stateful
    AEAD) scheme> <math|\<Pi\>> consists of:

    <\itemize-dot>
      <item>A probabilistic key generation algorithm (it is the AGKE in our
      case).

      <item>A stateful probabilistic encryption <math|<math|E(k, ad, m,
      st<rsub|E> )> \<rightarrow\> (c, st<rprime|'><rsub|E> )>.

      <item>A deterministic decryption algorithm <math|D(k, ad, c, st<rsub|D>
      ) \<rightarrow\> (ad, m, st<rprime|'><rsub|D> )>\ 

      which can output <math|ad> or <math|\<perp\>> as error and message
      <math|m> or <math|\<perp\>> as error.
    </itemize-dot>
  </definition>

  <\definition>
    A <strong|correct stateful AEAD scheme> is a stateful AEAD scheme
    <math|\<Pi\>>, which can correctly decrypt a ciphertext <math|c> to the
    corresponding message <math|m> for any sequences of message or output
    error in case the ciphertext does not correspond to the output of
    <math|E<around*|(|k|)>>.\ 
  </definition>

  <section|Adversarial Power>

  We will re-use these definitions to demonstrate similar routes for other
  adversaries considered by the threat models in later sections.

  <subsection|Adversarial power for AKE>

  The following set of functions models the AKE adversarial threats. The
  adversary for the authenticated key exchange can mount an attack through a
  sequence of calls to the functions, outlined below. The limitation on the
  order and condition of calling these functions is defined per adversary.\ 

  <\itemize>
    <item><math|*Execute<around*|(|plist|)>>: asks all parties in the
    <math|plist> to run (a new) AGKE protocol and <math|\<cal-A\>> will
    receive the execution transcript, i.e. can eavesdrop.

    <item><math|Send<rsub|U<rsub|i>><around*|(|\<Pi\><rsub|i><rsup|S>|)><around*|(|m|)>>
    \ sends a message <with|font-shape|italic|m> to the instance
    <math|\<Pi\><rsup|S><rsub|i>> as user <math|U<rsub|j>>. We assume that
    <with|font-shape|italic|m> contains information to identify the sender
    <math|U<rsub|j>>. <math|U<rsub|j>> will receive the reply transcript.
    Specifically, by sending <math|plist> messages it forces <math|U<rsub|i>>
    to initiate <math|\<Pi\><rsub|i><rsup|S>>.

    <item><with|font-series|bold|SKE(<label|MathJax-Element-62-Frame><label|MathJax-Span-805><label|MathJax-Span-806><label|MathJax-Span-807><label|MathJax-Span-808><label|MathJax-Span-809><label|MathJax-Span-810>\<Pi\><label|MathJax-Span-811><label|MathJax-Span-812><label|MathJax-Span-813>S<label|MathJax-Span-814><label|MathJax-Span-815><label|MathJax-Span-816>i<label|MathJax-Span-817>,<label|MathJax-Span-818>s<label|MathJax-Span-819>p<label|MathJax-Span-820>i<label|MathJax-Span-821><label|MathJax-Span-822>d<label|MathJax-Span-823><label|MathJax-Span-824><label|MathJax-Span-825>i)>:
    asks <label|MathJax-Element-63-Frame><label|MathJax-Span-826><label|MathJax-Span-827><label|MathJax-Span-828><label|MathJax-Span-829><label|MathJax-Span-830>\<Pi\><label|MathJax-Span-831><label|MathJax-Span-832><label|MathJax-Span-833>S<label|MathJax-Span-834><label|MathJax-Span-835><label|MathJax-Span-836>i
    to compute the subgroup key for the <label|MathJax-Element-64-Frame><label|MathJax-Span-837><label|MathJax-Span-838><label|MathJax-Span-839><label|MathJax-Span-840><label|MathJax-Span-841>s<label|MathJax-Span-842>p<label|MathJax-Span-843>i<label|MathJax-Span-844><label|MathJax-Span-845>d<label|MathJax-Span-846><label|MathJax-Span-847><label|MathJax-Span-848>i
    subsession. In response, <label|MathJax-Element-65-Frame><label|MathJax-Span-849><label|MathJax-Span-850><label|MathJax-Span-851><label|MathJax-Span-852><label|MathJax-Span-853>\<Pi\><label|MathJax-Span-854><label|MathJax-Span-855><label|MathJax-Span-856>S<label|MathJax-Span-857><label|MathJax-Span-858><label|MathJax-Span-859>i
    will either send a message or compute the subgroup key
    <label|MathJax-Element-66-Frame><label|MathJax-Span-860><label|MathJax-Span-861><label|MathJax-Span-862><label|MathJax-Span-863><label|MathJax-Span-864>k<label|MathJax-Span-865><label|MathJax-Span-866><label|MathJax-Span-867><label|MathJax-Span-868><label|MathJax-Span-869>s<label|MathJax-Span-870>p<label|MathJax-Span-871>i<label|MathJax-Span-872><label|MathJax-Span-873>d<label|MathJax-Span-874><label|MathJax-Span-875><label|MathJax-Span-876>i
    depending on the state of <label|MathJax-Element-67-Frame><label|MathJax-Span-877><label|MathJax-Span-878><label|MathJax-Span-879><label|MathJax-Span-880><label|MathJax-Span-881>\<Pi\><label|MathJax-Span-882><label|MathJax-Span-883><label|MathJax-Span-884>S<label|MathJax-Span-885><label|MathJax-Span-886><label|MathJax-Span-887>i.
    This can be invoked only once per input.

    <item><with|font-series|bold|RevealGK(<math|>)>:
    <label|MathJax-Element-69-Frame><label|MathJax-Span-899><label|MathJax-Span-900><label|MathJax-Span-901><label|MathJax-Span-902><label|MathJax-Span-903>\<Pi\><label|MathJax-Span-904><label|MathJax-Span-905><label|MathJax-Span-906>S<label|MathJax-Span-907><label|MathJax-Span-908><label|MathJax-Span-909>i
    gives <label|MathJax-Element-70-Frame><label|MathJax-Span-910><label|MathJax-Span-911><label|MathJax-Span-912><label|MathJax-Span-913><label|MathJax-Span-914>s<label|MathJax-Span-915><label|MathJax-Span-916>k<label|MathJax-Span-917><label|MathJax-Span-918><label|MathJax-Span-919>i
    to <label|MathJax-Element-71-Frame><label|MathJax-Span-920><label|MathJax-Span-921><label|MathJax-Span-922><label|MathJax-Span-923><label|MathJax-Span-924><label|MathJax-Span-925><label|MathJax-Span-926><label|MathJax-Span-927><label|MathJax-Span-928>A<label|MathJax-Span-929><label|MathJax-Span-930><label|MathJax-Span-931>a
    if it has accepted (as described in Definition III.3).

    <item><with|font-series|bold|RevealSK>:
    <label|MathJax-Element-73-Frame><label|MathJax-Span-946><label|MathJax-Span-947><label|MathJax-Span-948><label|MathJax-Span-949><label|MathJax-Span-950>\<Pi\><label|MathJax-Span-951><label|MathJax-Span-952><label|MathJax-Span-953>S<label|MathJax-Span-954><label|MathJax-Span-955><label|MathJax-Span-956>i
    gives the <label|MathJax-Element-74-Frame><label|MathJax-Span-957><label|MathJax-Span-958><label|MathJax-Span-959><label|MathJax-Span-960><label|MathJax-Span-961>s<label|MathJax-Span-962>u<label|MathJax-Span-963>b<label|MathJax-Span-964><label|MathJax-Span-965>k<label|MathJax-Span-966><label|MathJax-Span-967><label|MathJax-Span-968>T<label|MathJax-Span-969><label|MathJax-Span-970><label|MathJax-Span-971>i
    to <label|MathJax-Element-75-Frame><label|MathJax-Span-972><label|MathJax-Span-973><label|MathJax-Span-974><label|MathJax-Span-975><label|MathJax-Span-976><label|MathJax-Span-977><label|MathJax-Span-978><label|MathJax-Span-979><label|MathJax-Span-980>A<label|MathJax-Span-981><label|MathJax-Span-982><label|MathJax-Span-983>a
    if it has been computed for subsession <with|font-shape|italic|T>.

    <item>RevealPeer(<math|\<Pi\><rsub|i><rsup|S>>,<math|U<rsub|j>>): When
    the <verbatim|<math|\<cal-A\>>> calls this function, it will be provided
    with the <math|p2p> key <math|k<rsub|i,j><rsup|S>>, if it is already
    computed.

    <item><with|font-series|bold|Corrupt(<label|MathJax-Element-76-Frame><label|MathJax-Span-984><label|MathJax-Span-985><label|MathJax-Span-986><label|MathJax-Span-987><label|MathJax-Span-988>U<label|MathJax-Span-989><label|MathJax-Span-990><label|MathJax-Span-991>i)>:
    <label|MathJax-Element-77-Frame><label|MathJax-Span-992><label|MathJax-Span-993><label|MathJax-Span-994><label|MathJax-Span-995><label|MathJax-Span-996>U<label|MathJax-Span-997><label|MathJax-Span-998><label|MathJax-Span-999>i
    gives its long-term secret key to <label|MathJax-Element-78-Frame><label|MathJax-Span-1000><label|MathJax-Span-1001><label|MathJax-Span-1002><label|MathJax-Span-1003><label|MathJax-Span-1004><label|MathJax-Span-1005><label|MathJax-Span-1006><label|MathJax-Span-1007><label|MathJax-Span-1008>A<label|MathJax-Span-1009><label|MathJax-Span-1010><label|MathJax-Span-1011>a
    (but not the session key).
  </itemize>

  <\definition>
    <strong|AKE-Security of P2P Keys>: Let <math|\<cal-P\>> be a <math|GKE+P >
    protocol and <math|b> a uniformly chosen bit. Adversary
    <math|\<cal-A\><rsub|p2p>> is allowed to invoke all adversarial queries.  At
    some point the Adversary runs
    <math|TestPeer<around*|(|\<Pi\><rsub|i><rsup|S>\<nocomma\>,U<rsub|j>|)>> for
    some fresh instance User pair
    <math|<around*|(|\<Pi\><rsub|i><rsup|S>\<nocomma\>,U<rsub|j>|)>> which
    remains fresh. <math|\<cal-A\><rsub|p2p>> is allowed to continue the
    adversarial queries provided the test pair remains fresh. Finally
    <math|\<cal-A\><rsub|p2p>> outputs a bit <math|b<rprime|'>>. The adversarial
    advantage is defined as

    <\equation*>
      Adv<rsub|\<cal-A\><rsub|p2p>><around*|(|\<cal-P\>|)>\<assign\><around*|\||2Pr<around*|(|b<rprime|'>=b|)>-1|\|>
    </equation*>

    We say the <math|\<cal-P\>> is secure if the advantage is negligible.
  </definition>

  <\definition>
    <dueto|<cite|ACMP10> Definition 5 AKE-Security of group Keys>: Let
    <math|\<cal-P\>> be a correct GKE+P protocol and b a uniformly chosen bit.
    By <math|Game<rsub|\<cal-A\><rsub|GKE>><around*|(|\<cal-P\>,\<kappa\>|)>>,we
    define the following adversarial game, which involves a PPT adversary
    <math|\<cal-A\><rsub|GKE>> that is given access to all queries:

    \U <math|\<cal-A\><rsub|GKE>> interacts via queries;

    \U at some point <math|\<cal-A\><rsub|GKE>> asks a <math|TestGK(
    \<Pi\><rsup|\<cal-S\>><rsub|i>)> query for some instance
    <math|\<Pi\><rsub|i><rsup|\<cal-S\>>> which is (and remains) fresh;

    \U <math|\<cal-A\><rsub|GKE>> continues interacting via queries;

    \U when <math|\<cal-A\><rsub|GKE>> terminates, it outputs a bit, which is
    set as the output of the game. We define:

    <\equation*>
      Adv<rsub|\<cal-A\><rsub|GKE>><around*|(|\<cal-P\>,\<kappa\>|)>\<assign\><around*|\||2Pr<around*|[|Game<rsub|\<cal-A\><rsub|GKE>><around*|(|\<cal-P\>,\<kappa\>|)>=b<rsub|>|]>-1|\|>
    </equation*>

    We say that <math|\<cal-P\>> provides GKE-security if the maximum of this
    advantage over all possible PPT adversaries <math|\<cal-A\><rsub|GKE>> is
    negligible.

    \;
  </definition>

  <\definition>
    <dueto|<cite|ACMP10> Definition 6 AKE Security of subgroup keys>: Let P be
    a correct GKE+S protocol and b a uniformly chosen bit. By Game ake-s,b

    A,P (\<kappa\>) we define the following adversarial game, which involves
    a PPT adversary A that is given access to all queries:

    \U A interacts via queries;

    \U at some point A asks a TestSK(\<Pi\> i s , spid si ) query for some
    instance-subgroup pair

    (\<Pi\> i s , spid si ) which is (and remains) fresh;

    \U A continues interacting via queries;

    \U when A terminates, it outputs a bit, which is set as the output of the
    game.

    We define

    <\equation*>
      \;

      Adv<rsub|\<cal-A\><rsub|S-GKE>> <around*|(|\<cal-P\>,\<kappa\>|)>\<assign\><around*|\||2Pr[Game(\<kappa\>)=b]-1|\|>

      \;
    </equation*>

    and denote with Adv ake-s(\<kappa\>) the maximum advantage over all PPT
    adversaries A. We say that P provides AKE-security of subgroup keys if
    this advantage is negligible.
  </definition>

  <subsection|<label|Secure_arty_Channel_Adversary>Secure Multi-party Channel
  Adversary>

  The desirable way to define an adversary for a multi-party chat session is
  a secure channel model similar to the two-party secure channels described
  in <cite|CaKr01>, <cite|JKSS12> and <cite|KPW13>.
  As such, we set the <em|authenticated and confidential channel
  establishment> (ACCE) protocol as our starting point. In this regard, we
  would like to prove that <math|<around*|(|n+1|)>sec> is an ACCE protocol.
  It is argued in <cite|JKSS12> that if a scheme provides a secure AKE and
  the symmetric encryption of the session communication satisfies the
  suitable confidentiality and integrity criteria, then one can conlude that
  the scheme is an ACCE protocol (although the inverse statement is not
  true). Following this path, we define the adversary for the communication
  phase of a secure multi-party chat session. We use the Definition 3.2 from
  <cite|BHMS15> instead of Definition 6 in <cite|JKSS12>, because hiding the
  length of the conversation is not considered as a security property of
  <math|<around*|(|n+1|)>sec>.

  <subsubsection|<label|Definition_of_Adversaries_and_their_advantages_2>Definition
  of Adversaries and their advantages>

  Based on Definition <reference|defn-AEAD>, the adversary against an AEAD is
  defined as follows:

  <\definition>
    <dueto|<cite|BHMS15> Definition 3.2><label|defn-aead-adv>: Let
    <math|\<Pi\>> be a stateful AEAD scheme and let A be a PPT adversarial
    algorithm. Let <math|i \<in\> {1, . . . , 4}> and let <math|b \<in\> {0,
    1}>. The stateful AEAD experiment for <math|\<Pi\>> with condition
    <math|cond<rsub|i>> and bit b is given by
    <math|Exp<rsup|aead<rsub|i>-b><around*|(|\<Pi\>,\<cal-A\>|)><rsup|>> as
    defined in <cite|BHMS15> Figure 4. The adversaries' advantage is defined
    as

    <\equation*>
      Adv<rsup|aead<rsub|i>><around*|(||)><rsub|\<Pi\>,\<cal-A\><rsub|aead<rsub|i>>>\<assign\>Pr<around*|[|Exp<rsup|Exp<rsup|aead<rsub|i>-1>>(\<Pi\>,\<cal-A\>)=1|]>\<minus\>Pr<around*|[|Exp<rsup|Exp<rsup|aead<rsub|i>-0>>(\<Pi\>,\<cal-A\>)=1|]>
    </equation*>

    \;
  </definition>

  <subsection|<label|Message_Origin_Authentication_Adversary>Message Origin
  Authentication Adversary>

  Any manipulation of data by an outsider is modeled in the AEAD adversary as
  described in Definition <reference|defn-aead-adv>.
  <math|<around*|(|n+1|)>sec>, however, also needs to protect insiders from
  forging messages on behalf of each other. That is why each participant
  executes a sign and encrypts a function before sending their authenticated
  ephemeral signing key. The message origin adversary model is based on a
  typical adversary for a signature scheme such as the one presented in
  [PVY00].

  <subsubsection|<label|Adversarial_power_2>Adversarial power>

  In addition to adversarial functions defined in Section
  <reference|sect-adversaries>, we must define the following function
  to allow for the adversary using the chosen-message attack.

  <\itemize>
    <item><with|font-series|bold|MakeSend<around*|(|<math|\<Pi\><rsub|i><rsup|\<cal-S\>>,\<Pi\><rsub|j><rsup|\<cal-S\>>,m>|)>>
    causes the <math|\<Pi\><rsub|i><rsup|\<cal-S\>>> to sign and send a valid
    message <with|font-shape|italic|m> to instance
    <math|\<Pi\><rsub|j><rsup|\<cal-S\>>>. <math|\<cal-A\><rsub|orig>> will
    receive the transcript including the signature.
  </itemize>

  <subsubsection|<label|Definition_of_Adversary>Definition of the Adversary>

  <\definition>
    <label|defn-orig-adv><strong|Message Origin Authentication Adversary>:
    <math|\<cal-A\><rsub|orig>> is a polynomial time algorithm which has access
    to the <with|font-series|bold|Corrupt>, <with|font-series|bold|Send>,
    <with|font-series|bold|Reveal> and <with|font-series|bold|MakeSend>
    functions. The output of the algorithm should be a message <math|m>
    sent to instance <math|\<Pi\><rsub|j><rsup|\<cal-S\>>>. The scheme is
    secure against the message origin adversary if the probability in which
    <math|\<Pi\><rsup|\<cal-S\>><rsub|j>> believes that
    <with|font-shape|italic|m> has originated from an uncorrupted participant
    <math|U<rsub|i>> is negligible under assumption of the hardness of the
    Discrete Logarithm Problem.
  </definition>

  <section|Security of Triple Diffie-Hellman Authentication><label|sect-tdh>

  <subsection|The Triple Diffie-Hellman Protocol>

  <\float|float|tbh>
    <\big-table|<tabular|<tformat|<table|<row|<cell|Round
    1>|<cell|<math|A\<rightarrow\>B: <rprime|''>A<rprime|''>,g<rsup|a>>>|<cell|<math|B\<rightarrow\>A:<rprime|''>B<rprime|''>,g<rsup|b>>>>|<row|<cell|Key
    Computation>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|b>|)><rsup|A>\|<around*|(|g<rsup|B>|)><rsup|a>\|<around*|(|g<rsup|b>|)><rsup|a>|)>>>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|A>|)><rsup|b>\|<around*|(|g<rsup|a>|)><rsup|B>\|<around*|(|g<rsup|a>|)><rsup|b>|)>>>>|<row|<cell|Round
    2>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,A|)>|)>>>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,B|)>|)>>>>>>>>
      Triple Diffie-Hellman protocol<label|tabl-tdh-protocol>
    </big-table>
  </float>Assuming that <math|A> and <math|B> are represented by long-term
  public keys <math|g<rsup|A>> and <math|g<rsup|B>> respectively:

  <subsection|The deniablity of TDH>

  <label|sect-tdh-sec> We will prove a parallel to Theorem 4 <cite|GKR06>
  which proves the deniability of SKEME. We use the notation introduced in
  Section <reference|sect-deniabl-adv>. Following the same notation:

  <\definition>
    By <math|Adv<rsub|deny><rsup|\<ast\>>> we refer to the party which
    represents the interaction of the Simulator <math|Sim> with the
    adversary. In other words, <math|Adv<rsup|\<ast\>><rsub|deny>> has access
    to all information which <math|Adv<rsub|deny>> possesses.
  </definition>

  <\theorem>
    If Computational Diffie-Hellman (CDH) is intractable, then Triple
    DH Algorithm is deniable.
  </theorem>

  <\proof>
    We build a <math|Sim<rsub|>> which interacts with <math|Adv<rsub|deny>>. We
    show that if <math|\<cal-J\>> is able to distinguish
    <math|Trans<rsub|Sim>> from <math|Trans<rsub|Real>>, they should be
    able to solve CDH as well.

    Intuitively, when <math|\<cal-A\><rsub|deny>> sends <math|g<rsup|a>> to
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>>,
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>><math|> inquires
    <math|\<cal-A\><rsub|deny>> for <math|a>, in this way
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>> also can compute the
    same key <math|k> by asking <math|\<cal-A\><rsub|deny><rsup|\<ast\>>>. If
    <math|\<cal-A\><rsub|deny>> has chosen
    <math|g<rsup|a>\<in\>Tr<around*|(|B|)>> or has just chosen a random element
    of the group without knowing its DLP, then <math|\<cal-S\><rsub|deny>>
    will choose a random exponent <math|a<rprime|'>> and compute the key
    <math|k> based on that and the confirmation value using <math|k>. Due to
    the difficulty of CDH, this value is indistinguishable from a
    <math|k> generated by <math|B>.

    Now we suppose that the TDH is not deniable and we build a solver for CDH.
    First we note that if <math|\<cal-A\><rsub|deny>> engages in an honest
    interaction with <math|B>, there is no way that <math|\<cal-J\>> can
    distinguish between the
    <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>> and
    <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>>. This is because
    <math|\<cal-A\><rsub|deny>> is able to generate the very exact transcript
    without the help of <math|B>. Therefore, logically, the only possibility for
    <math|\<cal-J\>> to distinguish
    <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>> and
    <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>> is when
    <math|\<cal-A\><rsub|deny>> presents <math|\<cal-J\>> with a transcript that
    <math|\<cal-A\><rsub|deny>> is not able to generate itself.  The only
    variable that <math|\<cal-A\><rsub|deny>> has control over in the course of
    the exchange is <math|g<rsup|a>> and therefore the only way
    <math|\<cal-A\><rsub|deny>> is able to claim that it was unable to generate
    the genuine \ <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>> is
    by sending <math|g<rsup|a>> in which <math|\<cal-A\><rsub|deny>> itself is
    not aware of the exponent <math|a>.

    In such case, assuming the undeniability of TDH, we have an
    <math|\<varepsilon\>> such that

    <\equation*>
      <math|>max<rsub|all \<cal-J\>><rsub|>\|2Pr(Output<around*|(|\<cal-J\>,Aux|)>
      = b) -1\|\<gtr\>\<varepsilon\>
    </equation*>

    The solver <math|\<cal-A\><rsub|CDH>> receives a triple
    <math|<around*|(|g,g<rsup|a>,g<rsup|b>|)>> and should compute <math|g<rsup|a
    b>>. To that end, assuming long-term identity <math|g<rsup|A>> for some
    <math|\<cal-A\><rsub|deny>>, it engages in a TDH key exchange with a
    hypothetical automated party <math|\<cal-A\><rsup|\<ast\>>> with long-term
    private key <math|B> who generates <math|g<rsup|b>> as the ephemeral key as
    well.  <math|\<cal-A\><rsub|CDH>> then tosses a coin and, based on the
    result, it either chooses a random <math|a<rprime|'>> and computes
    <math|g<rprime|'>=g<rsup|a<rprime|'>>> or sets <math|g<rprime|'>=g<rsup|a>,>
    then it submits <math|h<rsub|0>=H<around*|(|g<rsup|b><rsup|
    A>\<nocomma\>,g<rprime|'><rsup|B>,g<rsup|b a<rprime|'>>|)>> alongside with
    <math|<around*|(|g<rsup|B>,g<rsup|b>|)>> to the <math|\<cal-J\>> as a proof
    of engagement with <math|\<cal-A\><rsup|\<ast\>>>. Due to the undeniability
    assumption,

    <\equation*>
      Output<around*|(|\<cal-J\>,Aux|)><around*|(|h<rsub|0>,<around*|(|A,g<rsup|a>,B,g<rsup|b>|)>|)>=b
    </equation*>

    with significant probability, as it means <math|\<cal-J\>> is able to
    distinguish <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>>
    and <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>> with high
    probability. Therefore <math|\<cal-J\>> is able to decide if:

    <\equation*>
      h<rsub|0><long-arrow|\<rubber-equal\>|?>\<nocomma\>H<around*|(|g<rsup|b
      A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>,<around*|(|g<rsup|a>|)><rsup|b>|)>
    </equation*>

    Because <math|H> is a random oracle, the only way the judge is able to
    distinguish the second value from the real value is to have knowledge
    about the exact pre-image: <math|g<rsup|b
    A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>,<around*|(|g<rsup|a>|)><rsup|b>>.
    Using the information in the transcript, <math|\<cal-J\>> can compute
    <math|g<rsup|b A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>>, but still
    has to compute <math|g<rsup|ab>> using <math|g<rsup|a>> and
    <math|g<rsup|b>> with high probability without knowing <math|a> or
    <math|b>. At this point, <math|\<cal-A\><rsub|CDH>> is publishing the
    value of <math|g<rsup|a b>>.

    \;
  </proof>

  <subsection|Security of TDH as a two-party Authenticated Key Exchange>

  In this section we prove that TDH is a secure two-party authenticated key
  exchange. we do so in the AKE security model proposed in
  <math|<cite|Ma09>>. This is because (n+1)sec's key exchange protocol is a
  variant of the protocol proposed in <cite|AMP10>, which is designed to
  satisfy all three AKE models proposed in <cite|Ma09> and <cite|AMP10>.
  Furthermore, based on the security properties required by (n+1)sec as a
  secure multi-party chat protocol, we believe these models provide adequate
  security for real-world threat scenarios.

  <\theorem>
    If the GDH problem is hard in <math|\<bbb-G\>>, then TDH protocol
    explained in Table <reference|tabl-tdh-protocol>, is secure in AKE model,
    with the advantage of the adversary bounded by:

    <\equation*>
      Adv<rsub|\<cal-A\><rsub|p2p><around*|(|k|)>\<leqslant\>\<cal-O\><around*|(|q<rsup|2>|)>>/Q
    </equation*>
  </theorem>

  Where <math|q> is the maximum number of queries by the adversary.\ 

  <\proof>
    Suppose that
    <math|k<rsub|test>=H<around*|(|<around*|(|g<rsup|b>|)><rsup|A>\|<around*|(|g<rsup|B>|)><rsup|a>\|<around*|(|g<rsup|b>|)><rsup|a>|)>>.
    Assuming that <math|H> is a PRF (SHA-256 in the case of (n+1)sec), the only
    way that adversary <math|\<cal-A\><rsub|p2p>> can distinguish
    <math|k<rsub|test>> from a random value <math|k<rprime|'>> is to compute all
    elements of the triplet
    <math|<around*|(|g<rsup|b>|)><rsup|A>\<nocomma\>,<around*|(|g<rsup|B>|)><rsup|a>,<around*|(|g<rsup|b>|)><rsup|a>>.

    We show how to construct a GDH solver using an <math|\<cal-A\><rsub|p2p>>
    that can compute all of the three above. Assuming that the test session is
    Fresh, then the adversary cannot corrupt either <math|A> or <math|B> and
    can request session reveal on the test session. Therefore it does not
    have either access to <math|a> or <math|b>.

    Now suppose simulator <math|\<cal-S\>> has access to the Adversary
    <math|\<cal-A\>> oracle which is able to compute the Triple
    Diffie-Hellman inside the paranthesis. <math|\<cal-S\>> needs to solve
    <math|g<rsup|a b>> for a given <math|g<rsup|a>> and <math|g<rsup|b>>. As
    such, it generates a transcript to set up a session between <math|A> and
    <math|B> while inserting <math|g<rsup|a>> and <math|g<rsup|b>> as
    exchanged keys.

    Assuming the above, the adversary can compute the last token which is the
    solution to CDH.

    \ 
  </proof>

  <\theorem>
    If the GDH problem is hard in <math|\<bbb-G\>>, then (n+1)sec protocol is
    secure against <math|\<cal-A\><rsub|p2p>>
    adversary.<label|thrm-np1sec-p2p-sec>
  </theorem>

  <\proof>
    We argue that the AKE security for the (n+1)Sec <math|p2p> keys follows,
    similarly, from the proof of Theorem 8 <cite|AMP10> which proves
    the security of BD+P protocol.\ 

    In fact, we follow the same sequence of games for games <math|G<rsub|0>>
    and <math|G<rsub|1>>.\ 

    For game <math|G<rsub|2>>, we note that contrary to mBP+P, which signs
    the second round message with <math|LPK<rsub|i>> for authentication, the
    adversary has two ways to forge the authentication and force the other
    party to accept a wrong key. One is to forge the signature generated by
    the ephemeral key. This is basically covered by <math|G<rsub|2>>.
    However, another way is to forge the authentication token we simulate in
    <math|G<rsub|2><rprime|'>.>\ 

    <verbatim|<strong|<math|\<b-G\><rsub|2><rprime|'>>>.> In this game, we
    abort the simulation if <math|\<cal-A\><rsub|p2p>> queries
    <math|Send<around*|(|U<rsub|i>\<nocomma\>,kc<rsub|i,j>|)>> with a valid
    confirmation where neither <math|U<rsub|i>> or <math|U<rsub|j>> is not
    corrupted. To do so, <math|\<cal-A\><rsub|p2p>> needs to generate
    <math|H<around*|(|k<rsub|i j>\|U<rsub|i>|)>>. Assuming that <math|H> is
    PRF, this is only possible if <math|\<cal-A\><rsub|p2p>> has successfully
    computed <math|k<rsub|i j>>, which in part necessitates
    <math|\<cal-A\><rsub|p2p>> computing <math|g<rsup|b LPK<rsub|i>>> to be
    able to impersonate <math|A> to <math|B>. Knowing neither secret <math|b>
    nor <math|LPK<rsub|i>>, the advantage of <math|\<cal-A\><rsub|p2p>> is
    bounded by its advantage in solving GDH. The adversary needs to solve all
    three GDH problems. Therefore we have:

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|2>|]>-Pr<around*|[|Win<rsub|2<rprime|'>>|]>|\|>\<less\>q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    In fact, the only difference in the proof is related to <math|G<rsub|6>>.
    As <math|k<rsub|i j>> is computed as <math|H<around*|(|g<rsup|A
    b><around*|\||g<rsup|B a>|\|>g<rsup|a b>|)>>. Therefore simulator delta
    will output <math|H<rprime|'><around*|(|g<rsup|A>\|g<rsup|B>\|g<rsup|a>\|g<rsup|b>|)>>.
    However, because <math|H> is a perfect PRF, this remains
    indistinguishable unless the adversary has advantage on computing
    <math|g<rsup|A b>,g<rsup|B a>,g<rsup|a b>>.

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|6>|]>-Pr<around*|[|Win<rsub|5>|]>|\|>\<less\>q
      H<rsub|p><around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    Consequently, the overall advantage of <math|\<cal-A\><rsub|p2p>>
    bar its advantage in transition from <math|G<rsub|2>> to
    <math|G<rsub|2<rprime|'>>> is smaller than their advantage in the
    original mBD+P protocol:

    <\equation*>
      Adv<rsup|p2p><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>\<less\>Adv<rsup|p2p><rsub|mBD+P>*<around*|(|\<kappa\>|)>+q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    This proves that <math|Adv<rsup|p2p><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>>
    is asymptotically the same as <math|Adv<rsup|p2p><rsub|mBD+P><around*|(|\<kappa\>|)>>.

    \;
  </proof>

  <section|Security of (n+1)sec authenticated group key
  exchange><label|sect-gke>

  In this section we prove the security of the (n+1)sec group key exchange in
  the proposed adversarial model. Because the key exchange is essentially
  FAGKE, with the only difference being that the traditional DH key exchange
  is replaced by TDH, we prove the security of the (n+1)sec GKE based on the
  security of FAKE.

  <subsection|Security of GKE>

  We recall that the GKE protocol in (n+1)sec is essentially the same as the
  FAGKE protocol, except that in <math|>(n+1)sec we have:

  <\equation*>
    k<rsub|i,i+1>=H<around*|(|g<rsup|LS<rsub|i>x<rsub|i+1>>,g<rsup|LS<rsub|i+1>x<rsub|i>>\<nocomma\>,g<rsup|x<rsub|i>x<rsub|i+1>>|)>
  </equation*>

  Whereas in FAGKE we have:

  <\equation*>
    k<rsub|i,i+1>=g<rsup|x<rsub|i>x<rsub|i+1>>
  </equation*>

  Therefore, to prove that <math|<around*|(|n+1|)>>sec is secure, we need to
  prove Theorem <reference|thrm-np1sec-gke>:

  <\theorem>
    <label|thrm-np1sec-gke>If \ the GDH problem is hard, then the (n+1)sec
    key exchange provides AKE-security of group keys.
  </theorem>

  <\proof>
    We argue that the AKE security for the (n+1)sec group key follows,
    similarly, from the proof of Theorem 7 <cite|AMP10>, which proves
    the security of the BD+P protocol.

    In fact, we follow the same sequence of games for games <math|G<rsub|0>>
    and <math|G<rsub|1>>.\ 

    Similar to the case of <math|p2p> argued in Theorem
    <reference|thrm-np1sec-p2p-sec>, we need to expand game <math|G<rsub|2>>
    into two games of <math|G<rsub|2>> and <math|G<rsub|2><rprime|'>> to
    account both for the forgery of the signature and the TDH token. With the
    transitional advantage of

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|2>|]>-Pr<around*|[|Win<rsub|2<rprime|'>>|]>|\|>\<less\>q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    We proceed similarly with game <math|G<rsub|3>>. The difference in the
    proof is related to <math|G<rsub|4>>. \<Delta\> responds with
    <math|g<rsup|a<rsub|>>> and <math|g<rsup|b>> from the values of the GDH
    challenge. In this game, instead of computing <math|z<rprime|'><rsub|i >>
    as <math|H<around*|(|H<around*|(|g<rsup|A b><around*|\||g<rsup|B
    a>|\|>g<rsup|a b>|)>,sid|)>>, simulator \<Delta\> will output
    <math|H<rprime|'><around*|(|g<rsup|A>\|g<rsup|B>\|g<rsup|a>\|g<rsup|b>|)>>.
    However because <math|H> is a perfect PRF, this remains
    indistinguishable, unless the adversary has an advantage on computing
    <math|g<rsup|A b>,g<rsup|B a>,g<rsup|a b>>. So we have

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|6>|]>-Pr<around*|[|Win<rsub|5>|]>|\|>\<less\>q
      H<rsub|p><around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    \;

    The remaining argument for game <math|G<rsub|4>> is the same as
    <math|mBD+P> proof.\ 

    Consequently, the overall advantage of
    <math|\<cal-A\><rsup|ake-g><rsub|<around*|(|n+1|)>sec>> bar its advantage
    in transition from <math|G<rsub|2>> to <math|G<rsub|2<rprime|'>>>, is
    smaller than their advantage in the original mBD+P protocol:

    <\equation*>
      Adv<rsup|ake-g><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>\<less\>Adv<rsup|ake-g><rsub|mBD+P>*<around*|(|\<kappa\>|)>+q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    This proves that <math|Adv<rsup|ake-g><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>>
    is asymptotically the same as <math|Adv<rsup|ake-g><rsub|mBD+P><around*|(|\<kappa\>|)>>.

    \;
  </proof>

  <section|Security of the (n+1)sec authenticated group key exchange>

  <subsection|Security of <math|<around*|(|n+1|)>sec> as a secure channel>

  In this section we prove the following theorem.

  <\theorem>
    <label|thrm-np1sec-acce>(n+1)sec is an <em|authenticated and confidential
    channel establishment> (ACCE) protocol.
  </theorem>

  <\proof>
    Based on <cite|JKSS12>, a protocol which establish the confidential
    authentication key using a secure AKE and provides security against a
    stateful AEAD adversary during the secure session using the established
    key provides a secure (confidential and authenticated) channel. We have
    already established the GKE security of <math|<around*|(|n+1|)>sec>.
    Accordingly, we only need to prove that <math|<around*|(|n+1|)>sec>
    provides stateful AEAD security.

    To do so, we use <cite|BHMS15> Theorem 3.1 to prove that
    <math|<around*|(|n+1|)>sec> is a secure level-3 AEAD scheme.

    First, we recall the format of (n+1)sec messages:

    \;

    <code|:o3np1sec:Base64EnocodedMessage>\ 

    \;

    In which <verbatim|Base64EnocodedMessage> is encoded as

    <code|sid (DTHash), \ Signature (DTHashx2), Encrypted part of the
    message>.

    Where <math|sid> and Signature are associated data and the Encryption is
    provided by AES-GSM. Using the result of <cite|McVi04> and <cite|IOM12>, we
    know that AES-GSM is both IND-CCA and INT-CTXT. As such,
    <math|<around*|(|n+1|)>sec> is a <math|level-1> AEAD scheme.

    By considering the fact that <math|<around*|(|n+1|)>sec> messages have an
    <verbatim|own_sender_id> which is strictly increasing for each sender one by
    one for each message, alongside with <verbatim|session_id> and
    <verbatim|nonce>, we prove that <math|<around*|(|n+1|)>sec> encoding passes
    TEST4 described in <cite|BHMS15> Figure 3. Therefore, based on <cite|BHMS15>
    Theorem 3.1, (n+1)sec resists a level-4 stateful AEAD adversary.

    Now using the result of Theorem <reference|thrm-np1sec-gke>, based on the
    conclusion of <cite|JKSS12>, we conclude that (n+1)sec is an ACCE
    protocol.

    \;
  </proof>

  <section|<label|Message_Origin_Authentication_Adversary>Message Origin
  Authentication Adversary>

  Using the result of Theorem <reference|thrm-np1sec-acce>, we know that the
  (n+1)sec session transcript is secure against outsiders' manipulation.
  Therefore, it only remains to study the ability of the insiders of the
  session in forging messages against each other. To prevent such scenario,
  <math|<around*|(|n+1|)>sec> messages are signed by authenticated ephemeral
  keys. The authenticity of ephemeral keys is assured based on Theorem
  <reference|thrm-np1sec-p2p-sec> and has been established before the session
  starts. Therefore we only need to prove that <math|<around*|(|n+1|)>sec>
  provides security against signature forgery.

  As each participant executes a sign and encrypt function before sending
  their authenticated ephemeral signing key, the message origin adversary
  model is based on a typical adversary for a signature scheme such as the
  one presented in [PVY00].

  <\theorem>
    <math|<around*|(|n+1|)>sec> is secure against
    <math|\<cal-A\><rsub|orig>>.
  </theorem>

  <\proof>
    <math|<around*|(|n+1|)>sec> message is signed using the EdDSA signature
    scheme. According to <cite|BDLSY11>, the EdDSA system is a Schnorr based
    signature system and inherits the security properties of the Schnorr
    signature. According to <cite|PtSc00> Theorem 4, a chosen-message attack
    which can break the Schnorr scheme can solve the DLP of the underlying
    system in polynomial time. This will establish the security of
    <math|(n+1)sec> against the adversary defined in Definition
    <reference|defn-orig-adv>.

    \ 
  </proof>

  <section|Security of Transcript Consistency Assurance>

  <label|sect-tca>

  \;
</body>

<\references>
  <\collection>
    <associate|Adversarial_power_2|<tuple|?|?>>
    <associate|Adversary.27s_challenges_2|<tuple|2.2.1|?>>
    <associate|Definition_of_Adversaries_and_their_advantages_2|<tuple|?|?>>
    <associate|Definition_of_Adversary|<tuple|?|?>>
    <associate|MathJax-Element-1-Frame|<tuple|5|?>>
    <associate|MathJax-Element-10-Frame|<tuple|15|?>>
    <associate|MathJax-Element-11-Frame|<tuple|15|?>>
    <associate|MathJax-Element-12-Frame|<tuple|15|?>>
    <associate|MathJax-Element-13-Frame|<tuple|15|?>>
    <associate|MathJax-Element-14-Frame|<tuple|15|?>>
    <associate|MathJax-Element-146-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-147-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-148-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-149-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-15-Frame|<tuple|15|?>>
    <associate|MathJax-Element-150-Frame|<tuple|11|?>>
    <associate|MathJax-Element-151-Frame|<tuple|11|?>>
    <associate|MathJax-Element-152-Frame|<tuple|11|?>>
    <associate|MathJax-Element-153-Frame|<tuple|11|?>>
    <associate|MathJax-Element-155-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-156-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-157-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-158-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-159-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-16-Frame|<tuple|15|?>>
    <associate|MathJax-Element-160-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-161-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-162-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-17-Frame|<tuple|15|?>>
    <associate|MathJax-Element-18-Frame|<tuple|15|?>>
    <associate|MathJax-Element-19-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-2-Frame|<tuple|6|?>>
    <associate|MathJax-Element-20-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-21-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-22-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-23-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-24-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-25-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-26-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-27-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-28-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-29-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-3-Frame|<tuple|6|?>>
    <associate|MathJax-Element-30-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-31-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-32-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-33-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-34-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-35-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-36-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-37-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-38-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-39-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-4-Frame|<tuple|6|?>>
    <associate|MathJax-Element-40-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-41-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-42-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-43-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-44-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-45-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-46-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-47-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-48-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-49-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-5-Frame|<tuple|6|?>>
    <associate|MathJax-Element-50-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-51-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-52-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-53-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-54-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-55-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-56-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-57-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-58-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-59-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-6-Frame|<tuple|6|?>>
    <associate|MathJax-Element-60-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-61-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-62-Frame|<tuple|?|?>>
    <associate|MathJax-Element-63-Frame|<tuple|?|?>>
    <associate|MathJax-Element-64-Frame|<tuple|?|?>>
    <associate|MathJax-Element-65-Frame|<tuple|?|?>>
    <associate|MathJax-Element-66-Frame|<tuple|?|?>>
    <associate|MathJax-Element-67-Frame|<tuple|?|?>>
    <associate|MathJax-Element-68-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-69-Frame|<tuple|?|?>>
    <associate|MathJax-Element-7-Frame|<tuple|6|?>>
    <associate|MathJax-Element-70-Frame|<tuple|?|?>>
    <associate|MathJax-Element-71-Frame|<tuple|?|?>>
    <associate|MathJax-Element-72-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-73-Frame|<tuple|?|?>>
    <associate|MathJax-Element-74-Frame|<tuple|?|?>>
    <associate|MathJax-Element-75-Frame|<tuple|?|?>>
    <associate|MathJax-Element-76-Frame|<tuple|?|?>>
    <associate|MathJax-Element-77-Frame|<tuple|?|?>>
    <associate|MathJax-Element-78-Frame|<tuple|?|?>>
    <associate|MathJax-Element-8-Frame|<tuple|6|?>>
    <associate|MathJax-Element-9-Frame|<tuple|15|?>>
    <associate|MathJax-Span-1|<tuple|5|?>>
    <associate|MathJax-Span-10|<tuple|5|?>>
    <associate|MathJax-Span-100|<tuple|6|?>>
    <associate|MathJax-Span-1000|<tuple|?|?>>
    <associate|MathJax-Span-1001|<tuple|?|?>>
    <associate|MathJax-Span-1002|<tuple|?|?>>
    <associate|MathJax-Span-1003|<tuple|?|?>>
    <associate|MathJax-Span-1004|<tuple|?|?>>
    <associate|MathJax-Span-1005|<tuple|?|?>>
    <associate|MathJax-Span-1006|<tuple|?|?>>
    <associate|MathJax-Span-1007|<tuple|?|?>>
    <associate|MathJax-Span-1008|<tuple|?|?>>
    <associate|MathJax-Span-1009|<tuple|?|?>>
    <associate|MathJax-Span-101|<tuple|6|?>>
    <associate|MathJax-Span-1010|<tuple|?|?>>
    <associate|MathJax-Span-1011|<tuple|?|?>>
    <associate|MathJax-Span-102|<tuple|6|?>>
    <associate|MathJax-Span-103|<tuple|6|?>>
    <associate|MathJax-Span-104|<tuple|6|?>>
    <associate|MathJax-Span-105|<tuple|6|?>>
    <associate|MathJax-Span-106|<tuple|6|?>>
    <associate|MathJax-Span-107|<tuple|6|?>>
    <associate|MathJax-Span-108|<tuple|6|?>>
    <associate|MathJax-Span-109|<tuple|6|?>>
    <associate|MathJax-Span-11|<tuple|5|?>>
    <associate|MathJax-Span-110|<tuple|6|?>>
    <associate|MathJax-Span-111|<tuple|6|?>>
    <associate|MathJax-Span-112|<tuple|6|?>>
    <associate|MathJax-Span-113|<tuple|6|?>>
    <associate|MathJax-Span-114|<tuple|6|?>>
    <associate|MathJax-Span-115|<tuple|6|?>>
    <associate|MathJax-Span-116|<tuple|6|?>>
    <associate|MathJax-Span-117|<tuple|6|?>>
    <associate|MathJax-Span-118|<tuple|6|?>>
    <associate|MathJax-Span-119|<tuple|6|?>>
    <associate|MathJax-Span-12|<tuple|5|?>>
    <associate|MathJax-Span-120|<tuple|6|?>>
    <associate|MathJax-Span-121|<tuple|6|?>>
    <associate|MathJax-Span-122|<tuple|6|?>>
    <associate|MathJax-Span-123|<tuple|6|?>>
    <associate|MathJax-Span-124|<tuple|6|?>>
    <associate|MathJax-Span-125|<tuple|6|?>>
    <associate|MathJax-Span-126|<tuple|6|?>>
    <associate|MathJax-Span-127|<tuple|6|?>>
    <associate|MathJax-Span-128|<tuple|6|?>>
    <associate|MathJax-Span-129|<tuple|6|?>>
    <associate|MathJax-Span-13|<tuple|5|?>>
    <associate|MathJax-Span-130|<tuple|6|?>>
    <associate|MathJax-Span-131|<tuple|6|?>>
    <associate|MathJax-Span-132|<tuple|6|?>>
    <associate|MathJax-Span-133|<tuple|6|?>>
    <associate|MathJax-Span-134|<tuple|6|?>>
    <associate|MathJax-Span-135|<tuple|6|?>>
    <associate|MathJax-Span-136|<tuple|6|?>>
    <associate|MathJax-Span-137|<tuple|6|?>>
    <associate|MathJax-Span-138|<tuple|6|?>>
    <associate|MathJax-Span-139|<tuple|6|?>>
    <associate|MathJax-Span-14|<tuple|5|?>>
    <associate|MathJax-Span-140|<tuple|6|?>>
    <associate|MathJax-Span-141|<tuple|6|?>>
    <associate|MathJax-Span-142|<tuple|6|?>>
    <associate|MathJax-Span-143|<tuple|15|?>>
    <associate|MathJax-Span-144|<tuple|15|?>>
    <associate|MathJax-Span-145|<tuple|15|?>>
    <associate|MathJax-Span-146|<tuple|15|?>>
    <associate|MathJax-Span-147|<tuple|15|?>>
    <associate|MathJax-Span-148|<tuple|15|?>>
    <associate|MathJax-Span-149|<tuple|15|?>>
    <associate|MathJax-Span-15|<tuple|5|?>>
    <associate|MathJax-Span-150|<tuple|15|?>>
    <associate|MathJax-Span-151|<tuple|15|?>>
    <associate|MathJax-Span-152|<tuple|15|?>>
    <associate|MathJax-Span-153|<tuple|15|?>>
    <associate|MathJax-Span-154|<tuple|15|?>>
    <associate|MathJax-Span-155|<tuple|15|?>>
    <associate|MathJax-Span-156|<tuple|15|?>>
    <associate|MathJax-Span-157|<tuple|15|?>>
    <associate|MathJax-Span-158|<tuple|15|?>>
    <associate|MathJax-Span-159|<tuple|15|?>>
    <associate|MathJax-Span-16|<tuple|5|?>>
    <associate|MathJax-Span-160|<tuple|15|?>>
    <associate|MathJax-Span-161|<tuple|15|?>>
    <associate|MathJax-Span-162|<tuple|15|?>>
    <associate|MathJax-Span-163|<tuple|15|?>>
    <associate|MathJax-Span-164|<tuple|15|?>>
    <associate|MathJax-Span-165|<tuple|15|?>>
    <associate|MathJax-Span-166|<tuple|15|?>>
    <associate|MathJax-Span-167|<tuple|15|?>>
    <associate|MathJax-Span-168|<tuple|15|?>>
    <associate|MathJax-Span-169|<tuple|15|?>>
    <associate|MathJax-Span-17|<tuple|5|?>>
    <associate|MathJax-Span-170|<tuple|15|?>>
    <associate|MathJax-Span-171|<tuple|15|?>>
    <associate|MathJax-Span-172|<tuple|15|?>>
    <associate|MathJax-Span-173|<tuple|15|?>>
    <associate|MathJax-Span-174|<tuple|15|?>>
    <associate|MathJax-Span-175|<tuple|15|?>>
    <associate|MathJax-Span-176|<tuple|15|?>>
    <associate|MathJax-Span-177|<tuple|15|?>>
    <associate|MathJax-Span-178|<tuple|15|?>>
    <associate|MathJax-Span-179|<tuple|15|?>>
    <associate|MathJax-Span-18|<tuple|5|?>>
    <associate|MathJax-Span-180|<tuple|15|?>>
    <associate|MathJax-Span-181|<tuple|15|?>>
    <associate|MathJax-Span-182|<tuple|15|?>>
    <associate|MathJax-Span-183|<tuple|15|?>>
    <associate|MathJax-Span-184|<tuple|15|?>>
    <associate|MathJax-Span-185|<tuple|15|?>>
    <associate|MathJax-Span-186|<tuple|15|?>>
    <associate|MathJax-Span-187|<tuple|15|?>>
    <associate|MathJax-Span-188|<tuple|15|?>>
    <associate|MathJax-Span-189|<tuple|15|?>>
    <associate|MathJax-Span-19|<tuple|5|?>>
    <associate|MathJax-Span-190|<tuple|15|?>>
    <associate|MathJax-Span-191|<tuple|15|?>>
    <associate|MathJax-Span-192|<tuple|15|?>>
    <associate|MathJax-Span-193|<tuple|15|?>>
    <associate|MathJax-Span-194|<tuple|15|?>>
    <associate|MathJax-Span-195|<tuple|15|?>>
    <associate|MathJax-Span-196|<tuple|15|?>>
    <associate|MathJax-Span-197|<tuple|15|?>>
    <associate|MathJax-Span-198|<tuple|15|?>>
    <associate|MathJax-Span-199|<tuple|15|?>>
    <associate|MathJax-Span-2|<tuple|5|?>>
    <associate|MathJax-Span-20|<tuple|5|?>>
    <associate|MathJax-Span-200|<tuple|15|?>>
    <associate|MathJax-Span-201|<tuple|15|?>>
    <associate|MathJax-Span-202|<tuple|15|?>>
    <associate|MathJax-Span-203|<tuple|15|?>>
    <associate|MathJax-Span-204|<tuple|15|?>>
    <associate|MathJax-Span-205|<tuple|15|?>>
    <associate|MathJax-Span-2053|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2054|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2055|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2056|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2057|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2058|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2059|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-206|<tuple|15|?>>
    <associate|MathJax-Span-2060|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2061|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2062|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2063|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2064|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2065|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2066|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2067|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2068|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2069|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-207|<tuple|15|?>>
    <associate|MathJax-Span-2070|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2071|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2072|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2073|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2074|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2075|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2076|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2077|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2078|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2079|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-208|<tuple|15|?>>
    <associate|MathJax-Span-2080|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2081|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2082|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2083|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2084|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2085|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2086|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2087|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2088|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2089|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-209|<tuple|15|?>>
    <associate|MathJax-Span-2090|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2091|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2092|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2093|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2094|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2095|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2096|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2097|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2098|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2099|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-21|<tuple|5|?>>
    <associate|MathJax-Span-210|<tuple|15|?>>
    <associate|MathJax-Span-2100|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2101|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2102|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2103|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2104|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2105|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2106|<tuple|11|?>>
    <associate|MathJax-Span-2107|<tuple|11|?>>
    <associate|MathJax-Span-2108|<tuple|11|?>>
    <associate|MathJax-Span-2109|<tuple|11|?>>
    <associate|MathJax-Span-211|<tuple|15|?>>
    <associate|MathJax-Span-2110|<tuple|11|?>>
    <associate|MathJax-Span-2111|<tuple|11|?>>
    <associate|MathJax-Span-2112|<tuple|11|?>>
    <associate|MathJax-Span-2113|<tuple|11|?>>
    <associate|MathJax-Span-2114|<tuple|11|?>>
    <associate|MathJax-Span-2115|<tuple|11|?>>
    <associate|MathJax-Span-2116|<tuple|11|?>>
    <associate|MathJax-Span-2117|<tuple|11|?>>
    <associate|MathJax-Span-2118|<tuple|11|?>>
    <associate|MathJax-Span-2119|<tuple|11|?>>
    <associate|MathJax-Span-212|<tuple|15|?>>
    <associate|MathJax-Span-2120|<tuple|11|?>>
    <associate|MathJax-Span-2121|<tuple|11|?>>
    <associate|MathJax-Span-2122|<tuple|11|?>>
    <associate|MathJax-Span-2123|<tuple|11|?>>
    <associate|MathJax-Span-2124|<tuple|11|?>>
    <associate|MathJax-Span-2125|<tuple|11|?>>
    <associate|MathJax-Span-2126|<tuple|11|?>>
    <associate|MathJax-Span-2127|<tuple|11|?>>
    <associate|MathJax-Span-2128|<tuple|11|?>>
    <associate|MathJax-Span-2129|<tuple|11|?>>
    <associate|MathJax-Span-213|<tuple|15|?>>
    <associate|MathJax-Span-2130|<tuple|11|?>>
    <associate|MathJax-Span-2131|<tuple|11|?>>
    <associate|MathJax-Span-2132|<tuple|11|?>>
    <associate|MathJax-Span-2133|<tuple|11|?>>
    <associate|MathJax-Span-2134|<tuple|11|?>>
    <associate|MathJax-Span-2135|<tuple|11|?>>
    <associate|MathJax-Span-2136|<tuple|11|?>>
    <associate|MathJax-Span-2137|<tuple|11|?>>
    <associate|MathJax-Span-2138|<tuple|11|?>>
    <associate|MathJax-Span-2139|<tuple|11|?>>
    <associate|MathJax-Span-214|<tuple|15|?>>
    <associate|MathJax-Span-2140|<tuple|11|?>>
    <associate|MathJax-Span-2141|<tuple|11|?>>
    <associate|MathJax-Span-2142|<tuple|11|?>>
    <associate|MathJax-Span-2143|<tuple|11|?>>
    <associate|MathJax-Span-215|<tuple|15|?>>
    <associate|MathJax-Span-216|<tuple|15|?>>
    <associate|MathJax-Span-2161|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2162|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2163|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2164|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2165|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2166|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2167|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2168|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2169|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-217|<tuple|15|?>>
    <associate|MathJax-Span-2170|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2171|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2172|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2173|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2174|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2175|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2176|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2177|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2178|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2179|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-218|<tuple|15|?>>
    <associate|MathJax-Span-2180|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2181|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2182|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2183|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2184|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2185|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2186|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2187|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2188|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2189|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-219|<tuple|15|?>>
    <associate|MathJax-Span-2190|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2191|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2192|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2193|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2194|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2195|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2196|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2197|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2198|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2199|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-22|<tuple|5|?>>
    <associate|MathJax-Span-220|<tuple|15|?>>
    <associate|MathJax-Span-2200|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2201|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2202|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2203|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2204|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2205|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2206|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2207|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2208|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2209|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-221|<tuple|15|?>>
    <associate|MathJax-Span-2210|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2211|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2212|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2213|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2214|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2215|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2216|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2217|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2218|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2219|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-222|<tuple|15|?>>
    <associate|MathJax-Span-2220|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2221|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2222|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2223|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2224|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2225|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2226|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2227|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2228|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2229|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-223|<tuple|15|?>>
    <associate|MathJax-Span-2230|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2231|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2232|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2233|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2234|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2235|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2236|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2237|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2238|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2239|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-224|<tuple|15|?>>
    <associate|MathJax-Span-2240|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2241|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2242|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2243|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2244|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2245|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2246|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2247|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2248|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2249|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-225|<tuple|15|?>>
    <associate|MathJax-Span-2250|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2251|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2252|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2253|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2254|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2255|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2256|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2257|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2258|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2259|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-226|<tuple|15|?>>
    <associate|MathJax-Span-2260|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2261|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2262|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2263|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2264|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2265|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2266|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2267|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2268|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2269|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-227|<tuple|15|?>>
    <associate|MathJax-Span-2270|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2271|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2272|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2273|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2274|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2275|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2276|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2277|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2278|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2279|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-228|<tuple|15|?>>
    <associate|MathJax-Span-2280|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2281|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2282|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2283|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2284|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2285|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2286|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2287|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2288|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2289|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-229|<tuple|15|?>>
    <associate|MathJax-Span-2290|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2291|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2292|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2293|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2294|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2295|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2296|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2297|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2298|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2299|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-23|<tuple|5|?>>
    <associate|MathJax-Span-230|<tuple|15|?>>
    <associate|MathJax-Span-2300|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2301|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2302|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2303|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2304|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2305|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2306|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2307|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2308|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2309|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-231|<tuple|15|?>>
    <associate|MathJax-Span-2310|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2311|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2312|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2313|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2314|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2315|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2316|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2317|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2318|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2319|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-232|<tuple|15|?>>
    <associate|MathJax-Span-2320|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2321|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2322|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2323|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2324|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2325|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2326|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2327|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2328|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2329|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-233|<tuple|15|?>>
    <associate|MathJax-Span-2330|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2331|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2332|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2333|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2334|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2335|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2336|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2337|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2338|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2339|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-234|<tuple|15|?>>
    <associate|MathJax-Span-2340|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2341|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2342|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2343|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2344|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2345|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2346|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2347|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2348|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2349|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-235|<tuple|15|?>>
    <associate|MathJax-Span-2350|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2351|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2352|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2353|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2354|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2355|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2356|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2357|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2358|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2359|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-236|<tuple|15|?>>
    <associate|MathJax-Span-2360|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2361|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2362|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2363|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2364|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2365|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2366|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2367|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2368|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2369|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-237|<tuple|15|?>>
    <associate|MathJax-Span-2370|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2371|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2372|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2373|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2374|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-2375|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-238|<tuple|15|?>>
    <associate|MathJax-Span-239|<tuple|15|?>>
    <associate|MathJax-Span-24|<tuple|5|?>>
    <associate|MathJax-Span-240|<tuple|15|?>>
    <associate|MathJax-Span-241|<tuple|15|?>>
    <associate|MathJax-Span-242|<tuple|15|?>>
    <associate|MathJax-Span-243|<tuple|15|?>>
    <associate|MathJax-Span-244|<tuple|15|?>>
    <associate|MathJax-Span-245|<tuple|15|?>>
    <associate|MathJax-Span-246|<tuple|15|?>>
    <associate|MathJax-Span-247|<tuple|15|?>>
    <associate|MathJax-Span-248|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-249|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-25|<tuple|5|?>>
    <associate|MathJax-Span-250|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-251|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-252|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-253|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-254|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-255|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-256|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-257|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-258|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-259|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-26|<tuple|5|?>>
    <associate|MathJax-Span-260|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-261|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-262|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-263|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-264|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-265|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-266|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-267|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-268|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-269|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-27|<tuple|5|?>>
    <associate|MathJax-Span-270|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-271|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-272|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-273|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-274|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-275|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-276|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-277|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-278|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-279|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-28|<tuple|6|?>>
    <associate|MathJax-Span-280|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-281|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-282|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-283|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-284|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-285|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-286|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-287|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-288|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-289|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-29|<tuple|6|?>>
    <associate|MathJax-Span-290|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-291|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-292|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-293|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-294|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-295|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-296|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-297|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-298|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-299|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-3|<tuple|5|?>>
    <associate|MathJax-Span-30|<tuple|6|?>>
    <associate|MathJax-Span-300|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-301|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-302|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-303|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-304|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-305|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-306|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-307|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-308|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-309|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-31|<tuple|6|?>>
    <associate|MathJax-Span-310|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-311|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-312|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-313|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-314|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-315|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-316|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-317|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-318|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-319|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-32|<tuple|6|?>>
    <associate|MathJax-Span-320|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-321|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-322|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-323|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-324|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-325|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-326|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-327|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-328|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-329|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-33|<tuple|6|?>>
    <associate|MathJax-Span-330|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-331|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-332|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-333|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-334|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-335|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-336|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-337|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-338|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-339|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-34|<tuple|6|?>>
    <associate|MathJax-Span-340|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-341|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-342|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-343|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-344|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-345|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-346|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-347|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-348|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-349|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-35|<tuple|6|?>>
    <associate|MathJax-Span-350|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-351|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-352|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-353|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-354|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-355|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-356|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-357|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-358|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-359|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-36|<tuple|6|?>>
    <associate|MathJax-Span-360|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-361|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-362|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-363|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-364|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-365|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-366|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-367|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-368|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-369|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-37|<tuple|6|?>>
    <associate|MathJax-Span-370|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-371|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-372|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-373|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-374|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-375|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-376|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-377|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-378|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-379|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-38|<tuple|6|?>>
    <associate|MathJax-Span-380|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-381|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-382|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-383|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-384|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-385|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-386|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-387|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-388|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-389|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-39|<tuple|6|?>>
    <associate|MathJax-Span-390|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-391|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-392|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-393|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-394|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-395|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-396|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-397|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-398|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-399|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-4|<tuple|5|?>>
    <associate|MathJax-Span-40|<tuple|6|?>>
    <associate|MathJax-Span-400|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-401|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-402|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-403|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-404|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-405|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-406|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-407|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-408|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-409|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-41|<tuple|6|?>>
    <associate|MathJax-Span-410|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-411|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-412|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-413|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-414|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-415|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-416|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-417|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-418|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-419|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-42|<tuple|6|?>>
    <associate|MathJax-Span-420|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-421|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-422|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-423|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-424|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-425|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-426|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-427|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-428|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-429|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-43|<tuple|6|?>>
    <associate|MathJax-Span-430|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-431|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-432|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-433|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-434|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-435|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-436|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-437|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-438|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-439|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-44|<tuple|6|?>>
    <associate|MathJax-Span-440|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-441|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-442|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-443|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-444|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-445|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-446|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-447|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-448|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-449|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-45|<tuple|6|?>>
    <associate|MathJax-Span-450|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-451|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-452|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-453|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-454|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-455|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-456|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-457|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-458|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-459|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-46|<tuple|6|?>>
    <associate|MathJax-Span-460|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-461|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-462|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-463|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-464|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-465|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-466|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-467|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-468|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-469|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-47|<tuple|6|?>>
    <associate|MathJax-Span-470|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-471|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-472|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-473|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-474|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-475|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-476|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-477|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-478|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-479|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-48|<tuple|6|?>>
    <associate|MathJax-Span-480|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-481|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-482|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-483|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-484|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-485|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-486|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-487|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-488|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-489|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-49|<tuple|6|?>>
    <associate|MathJax-Span-490|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-491|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-492|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-493|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-494|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-495|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-496|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-497|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-498|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-499|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-5|<tuple|5|?>>
    <associate|MathJax-Span-50|<tuple|6|?>>
    <associate|MathJax-Span-500|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-501|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-502|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-503|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-504|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-505|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-506|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-507|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-508|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-509|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-51|<tuple|6|?>>
    <associate|MathJax-Span-510|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-511|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-512|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-513|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-514|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-515|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-516|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-517|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-518|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-519|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-52|<tuple|6|?>>
    <associate|MathJax-Span-520|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-521|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-522|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-523|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-524|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-525|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-526|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-527|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-528|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-529|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-53|<tuple|6|?>>
    <associate|MathJax-Span-530|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-531|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-532|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-533|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-534|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-535|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-536|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-537|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-538|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-539|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-54|<tuple|6|?>>
    <associate|MathJax-Span-540|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-541|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-542|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-543|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-544|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-545|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-546|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-547|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-548|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-549|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-55|<tuple|6|?>>
    <associate|MathJax-Span-550|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-551|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-552|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-553|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-554|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-555|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-556|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-557|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-558|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-559|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-56|<tuple|6|?>>
    <associate|MathJax-Span-560|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-561|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-562|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-563|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-564|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-565|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-566|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-567|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-568|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-569|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-57|<tuple|6|?>>
    <associate|MathJax-Span-570|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-571|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-572|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-573|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-574|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-575|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-576|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-577|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-578|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-579|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-58|<tuple|6|?>>
    <associate|MathJax-Span-580|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-581|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-582|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-583|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-584|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-585|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-586|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-587|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-588|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-589|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-59|<tuple|6|?>>
    <associate|MathJax-Span-590|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-591|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-592|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-593|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-594|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-595|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-596|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-597|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-598|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-599|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-6|<tuple|5|?>>
    <associate|MathJax-Span-60|<tuple|6|?>>
    <associate|MathJax-Span-600|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-601|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-602|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-603|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-604|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-605|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-606|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-607|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-608|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-609|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-61|<tuple|6|?>>
    <associate|MathJax-Span-610|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-611|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-612|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-613|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-614|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-615|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-616|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-617|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-618|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-619|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-62|<tuple|6|?>>
    <associate|MathJax-Span-620|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-621|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-622|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-623|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-624|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-625|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-626|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-627|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-628|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-629|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-63|<tuple|6|?>>
    <associate|MathJax-Span-630|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-631|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-632|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-633|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-634|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-635|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-636|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-637|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-638|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-639|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-64|<tuple|6|?>>
    <associate|MathJax-Span-640|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-641|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-642|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-643|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-644|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-645|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-646|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-647|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-648|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-649|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-65|<tuple|6|?>>
    <associate|MathJax-Span-650|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-651|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-652|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-653|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-654|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-655|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-656|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-657|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-658|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-659|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-66|<tuple|6|?>>
    <associate|MathJax-Span-660|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-661|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-662|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-663|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-664|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-665|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-666|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-667|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-668|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-669|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-67|<tuple|6|?>>
    <associate|MathJax-Span-670|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-671|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-672|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-673|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-674|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-675|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-676|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-677|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-678|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-679|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-68|<tuple|6|?>>
    <associate|MathJax-Span-680|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-681|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-682|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-683|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-684|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-685|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-686|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-687|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-688|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-689|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-69|<tuple|6|?>>
    <associate|MathJax-Span-690|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-691|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-692|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-693|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-694|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-695|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-696|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-697|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-698|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-699|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-7|<tuple|5|?>>
    <associate|MathJax-Span-70|<tuple|6|?>>
    <associate|MathJax-Span-700|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-701|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-702|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-703|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-704|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-705|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-706|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-707|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-708|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-709|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-71|<tuple|6|?>>
    <associate|MathJax-Span-710|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-711|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-712|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-713|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-714|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-715|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-716|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-717|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-718|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-719|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-72|<tuple|6|?>>
    <associate|MathJax-Span-720|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-721|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-722|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-723|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-724|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-725|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-726|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-727|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-728|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-729|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-73|<tuple|6|?>>
    <associate|MathJax-Span-730|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-731|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-732|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-733|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-734|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-735|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-736|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-737|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-738|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-739|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-74|<tuple|6|?>>
    <associate|MathJax-Span-740|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-741|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-742|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-743|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-744|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-745|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-746|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-747|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-748|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-749|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-75|<tuple|6|?>>
    <associate|MathJax-Span-750|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-751|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-752|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-753|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-754|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-755|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-756|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-757|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-758|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-759|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-76|<tuple|6|?>>
    <associate|MathJax-Span-760|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-761|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-762|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-763|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-764|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-765|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-766|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-767|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-768|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-769|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-77|<tuple|6|?>>
    <associate|MathJax-Span-770|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-771|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-772|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-773|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-774|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-775|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-776|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-777|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-778|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-779|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-78|<tuple|6|?>>
    <associate|MathJax-Span-780|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-781|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-782|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-783|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-784|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-785|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-786|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-787|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-788|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-789|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-79|<tuple|6|?>>
    <associate|MathJax-Span-790|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-791|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-792|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-793|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-794|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-795|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-796|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-797|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-798|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-799|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-8|<tuple|5|?>>
    <associate|MathJax-Span-80|<tuple|6|?>>
    <associate|MathJax-Span-800|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-801|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-802|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-803|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-804|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-805|<tuple|?|?>>
    <associate|MathJax-Span-806|<tuple|?|?>>
    <associate|MathJax-Span-807|<tuple|?|?>>
    <associate|MathJax-Span-808|<tuple|?|?>>
    <associate|MathJax-Span-809|<tuple|?|?>>
    <associate|MathJax-Span-81|<tuple|6|?>>
    <associate|MathJax-Span-810|<tuple|?|?>>
    <associate|MathJax-Span-811|<tuple|?|?>>
    <associate|MathJax-Span-812|<tuple|?|?>>
    <associate|MathJax-Span-813|<tuple|?|?>>
    <associate|MathJax-Span-814|<tuple|?|?>>
    <associate|MathJax-Span-815|<tuple|?|?>>
    <associate|MathJax-Span-816|<tuple|?|?>>
    <associate|MathJax-Span-817|<tuple|?|?>>
    <associate|MathJax-Span-818|<tuple|?|?>>
    <associate|MathJax-Span-819|<tuple|?|?>>
    <associate|MathJax-Span-82|<tuple|6|?>>
    <associate|MathJax-Span-820|<tuple|?|?>>
    <associate|MathJax-Span-821|<tuple|?|?>>
    <associate|MathJax-Span-822|<tuple|?|?>>
    <associate|MathJax-Span-823|<tuple|?|?>>
    <associate|MathJax-Span-824|<tuple|?|?>>
    <associate|MathJax-Span-825|<tuple|?|?>>
    <associate|MathJax-Span-826|<tuple|?|?>>
    <associate|MathJax-Span-827|<tuple|?|?>>
    <associate|MathJax-Span-828|<tuple|?|?>>
    <associate|MathJax-Span-829|<tuple|?|?>>
    <associate|MathJax-Span-83|<tuple|6|?>>
    <associate|MathJax-Span-830|<tuple|?|?>>
    <associate|MathJax-Span-831|<tuple|?|?>>
    <associate|MathJax-Span-832|<tuple|?|?>>
    <associate|MathJax-Span-833|<tuple|?|?>>
    <associate|MathJax-Span-834|<tuple|?|?>>
    <associate|MathJax-Span-835|<tuple|?|?>>
    <associate|MathJax-Span-836|<tuple|?|?>>
    <associate|MathJax-Span-837|<tuple|?|?>>
    <associate|MathJax-Span-838|<tuple|?|?>>
    <associate|MathJax-Span-839|<tuple|?|?>>
    <associate|MathJax-Span-84|<tuple|6|?>>
    <associate|MathJax-Span-840|<tuple|?|?>>
    <associate|MathJax-Span-841|<tuple|?|?>>
    <associate|MathJax-Span-842|<tuple|?|?>>
    <associate|MathJax-Span-843|<tuple|?|?>>
    <associate|MathJax-Span-844|<tuple|?|?>>
    <associate|MathJax-Span-845|<tuple|?|?>>
    <associate|MathJax-Span-846|<tuple|?|?>>
    <associate|MathJax-Span-847|<tuple|?|?>>
    <associate|MathJax-Span-848|<tuple|?|?>>
    <associate|MathJax-Span-849|<tuple|?|?>>
    <associate|MathJax-Span-85|<tuple|6|?>>
    <associate|MathJax-Span-850|<tuple|?|?>>
    <associate|MathJax-Span-851|<tuple|?|?>>
    <associate|MathJax-Span-852|<tuple|?|?>>
    <associate|MathJax-Span-853|<tuple|?|?>>
    <associate|MathJax-Span-854|<tuple|?|?>>
    <associate|MathJax-Span-855|<tuple|?|?>>
    <associate|MathJax-Span-856|<tuple|?|?>>
    <associate|MathJax-Span-857|<tuple|?|?>>
    <associate|MathJax-Span-858|<tuple|?|?>>
    <associate|MathJax-Span-859|<tuple|?|?>>
    <associate|MathJax-Span-86|<tuple|6|?>>
    <associate|MathJax-Span-860|<tuple|?|?>>
    <associate|MathJax-Span-861|<tuple|?|?>>
    <associate|MathJax-Span-862|<tuple|?|?>>
    <associate|MathJax-Span-863|<tuple|?|?>>
    <associate|MathJax-Span-864|<tuple|?|?>>
    <associate|MathJax-Span-865|<tuple|?|?>>
    <associate|MathJax-Span-866|<tuple|?|?>>
    <associate|MathJax-Span-867|<tuple|?|?>>
    <associate|MathJax-Span-868|<tuple|?|?>>
    <associate|MathJax-Span-869|<tuple|?|?>>
    <associate|MathJax-Span-87|<tuple|6|?>>
    <associate|MathJax-Span-870|<tuple|?|?>>
    <associate|MathJax-Span-871|<tuple|?|?>>
    <associate|MathJax-Span-872|<tuple|?|?>>
    <associate|MathJax-Span-873|<tuple|?|?>>
    <associate|MathJax-Span-874|<tuple|?|?>>
    <associate|MathJax-Span-875|<tuple|?|?>>
    <associate|MathJax-Span-876|<tuple|?|?>>
    <associate|MathJax-Span-877|<tuple|?|?>>
    <associate|MathJax-Span-878|<tuple|?|?>>
    <associate|MathJax-Span-879|<tuple|?|?>>
    <associate|MathJax-Span-88|<tuple|6|?>>
    <associate|MathJax-Span-880|<tuple|?|?>>
    <associate|MathJax-Span-881|<tuple|?|?>>
    <associate|MathJax-Span-882|<tuple|?|?>>
    <associate|MathJax-Span-883|<tuple|?|?>>
    <associate|MathJax-Span-884|<tuple|?|?>>
    <associate|MathJax-Span-885|<tuple|?|?>>
    <associate|MathJax-Span-886|<tuple|?|?>>
    <associate|MathJax-Span-887|<tuple|?|?>>
    <associate|MathJax-Span-888|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-889|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-89|<tuple|6|?>>
    <associate|MathJax-Span-890|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-891|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-892|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-893|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-894|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-895|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-896|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-897|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-898|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-899|<tuple|?|?>>
    <associate|MathJax-Span-9|<tuple|5|?>>
    <associate|MathJax-Span-90|<tuple|6|?>>
    <associate|MathJax-Span-900|<tuple|?|?>>
    <associate|MathJax-Span-901|<tuple|?|?>>
    <associate|MathJax-Span-902|<tuple|?|?>>
    <associate|MathJax-Span-903|<tuple|?|?>>
    <associate|MathJax-Span-904|<tuple|?|?>>
    <associate|MathJax-Span-905|<tuple|?|?>>
    <associate|MathJax-Span-906|<tuple|?|?>>
    <associate|MathJax-Span-907|<tuple|?|?>>
    <associate|MathJax-Span-908|<tuple|?|?>>
    <associate|MathJax-Span-909|<tuple|?|?>>
    <associate|MathJax-Span-91|<tuple|6|?>>
    <associate|MathJax-Span-910|<tuple|?|?>>
    <associate|MathJax-Span-911|<tuple|?|?>>
    <associate|MathJax-Span-912|<tuple|?|?>>
    <associate|MathJax-Span-913|<tuple|?|?>>
    <associate|MathJax-Span-914|<tuple|?|?>>
    <associate|MathJax-Span-915|<tuple|?|?>>
    <associate|MathJax-Span-916|<tuple|?|?>>
    <associate|MathJax-Span-917|<tuple|?|?>>
    <associate|MathJax-Span-918|<tuple|?|?>>
    <associate|MathJax-Span-919|<tuple|?|?>>
    <associate|MathJax-Span-92|<tuple|6|?>>
    <associate|MathJax-Span-920|<tuple|?|?>>
    <associate|MathJax-Span-921|<tuple|?|?>>
    <associate|MathJax-Span-922|<tuple|?|?>>
    <associate|MathJax-Span-923|<tuple|?|?>>
    <associate|MathJax-Span-924|<tuple|?|?>>
    <associate|MathJax-Span-925|<tuple|?|?>>
    <associate|MathJax-Span-926|<tuple|?|?>>
    <associate|MathJax-Span-927|<tuple|?|?>>
    <associate|MathJax-Span-928|<tuple|?|?>>
    <associate|MathJax-Span-929|<tuple|?|?>>
    <associate|MathJax-Span-93|<tuple|6|?>>
    <associate|MathJax-Span-930|<tuple|?|?>>
    <associate|MathJax-Span-931|<tuple|?|?>>
    <associate|MathJax-Span-932|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-933|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-934|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-935|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-936|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-937|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-938|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-939|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-94|<tuple|6|?>>
    <associate|MathJax-Span-940|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-941|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-942|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-943|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-944|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-945|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-946|<tuple|?|?>>
    <associate|MathJax-Span-947|<tuple|?|?>>
    <associate|MathJax-Span-948|<tuple|?|?>>
    <associate|MathJax-Span-949|<tuple|?|?>>
    <associate|MathJax-Span-95|<tuple|6|?>>
    <associate|MathJax-Span-950|<tuple|?|?>>
    <associate|MathJax-Span-951|<tuple|?|?>>
    <associate|MathJax-Span-952|<tuple|?|?>>
    <associate|MathJax-Span-953|<tuple|?|?>>
    <associate|MathJax-Span-954|<tuple|?|?>>
    <associate|MathJax-Span-955|<tuple|?|?>>
    <associate|MathJax-Span-956|<tuple|?|?>>
    <associate|MathJax-Span-957|<tuple|?|?>>
    <associate|MathJax-Span-958|<tuple|?|?>>
    <associate|MathJax-Span-959|<tuple|?|?>>
    <associate|MathJax-Span-96|<tuple|6|?>>
    <associate|MathJax-Span-960|<tuple|?|?>>
    <associate|MathJax-Span-961|<tuple|?|?>>
    <associate|MathJax-Span-962|<tuple|?|?>>
    <associate|MathJax-Span-963|<tuple|?|?>>
    <associate|MathJax-Span-964|<tuple|?|?>>
    <associate|MathJax-Span-965|<tuple|?|?>>
    <associate|MathJax-Span-966|<tuple|?|?>>
    <associate|MathJax-Span-967|<tuple|?|?>>
    <associate|MathJax-Span-968|<tuple|?|?>>
    <associate|MathJax-Span-969|<tuple|?|?>>
    <associate|MathJax-Span-97|<tuple|6|?>>
    <associate|MathJax-Span-970|<tuple|?|?>>
    <associate|MathJax-Span-971|<tuple|?|?>>
    <associate|MathJax-Span-972|<tuple|?|?>>
    <associate|MathJax-Span-973|<tuple|?|?>>
    <associate|MathJax-Span-974|<tuple|?|?>>
    <associate|MathJax-Span-975|<tuple|?|?>>
    <associate|MathJax-Span-976|<tuple|?|?>>
    <associate|MathJax-Span-977|<tuple|?|?>>
    <associate|MathJax-Span-978|<tuple|?|?>>
    <associate|MathJax-Span-979|<tuple|?|?>>
    <associate|MathJax-Span-98|<tuple|6|?>>
    <associate|MathJax-Span-980|<tuple|?|?>>
    <associate|MathJax-Span-981|<tuple|?|?>>
    <associate|MathJax-Span-982|<tuple|?|?>>
    <associate|MathJax-Span-983|<tuple|?|?>>
    <associate|MathJax-Span-984|<tuple|?|?>>
    <associate|MathJax-Span-985|<tuple|?|?>>
    <associate|MathJax-Span-986|<tuple|?|?>>
    <associate|MathJax-Span-987|<tuple|?|?>>
    <associate|MathJax-Span-988|<tuple|?|?>>
    <associate|MathJax-Span-989|<tuple|?|?>>
    <associate|MathJax-Span-99|<tuple|6|?>>
    <associate|MathJax-Span-990|<tuple|?|?>>
    <associate|MathJax-Span-991|<tuple|?|?>>
    <associate|MathJax-Span-992|<tuple|?|?>>
    <associate|MathJax-Span-993|<tuple|?|?>>
    <associate|MathJax-Span-994|<tuple|?|?>>
    <associate|MathJax-Span-995|<tuple|?|?>>
    <associate|MathJax-Span-996|<tuple|?|?>>
    <associate|MathJax-Span-997|<tuple|?|?>>
    <associate|MathJax-Span-998|<tuple|?|?>>
    <associate|MathJax-Span-999|<tuple|?|?>>
    <associate|Message_Origin_Authentication_Adversary|<tuple|?|?>>
    <associate|Secure_Multiparty_Channel_Adversary|<tuple|?|?>>
    <associate|Secure_arty_Channel_Adversary|<tuple|?|?>>
    <associate|auto-1|<tuple|1|1>>
    <associate|auto-10|<tuple|3.1|?>>
    <associate|auto-11|<tuple|1|?>>
    <associate|auto-12|<tuple|3.2|?>>
    <associate|auto-13|<tuple|3.3|?>>
    <associate|auto-14|<tuple|4|?>>
    <associate|auto-15|<tuple|4.1|?>>
    <associate|auto-16|<tuple|5|?>>
    <associate|auto-17|<tuple|5.1|?>>
    <associate|auto-18|<tuple|6|?>>
    <associate|auto-19|<tuple|7|?>>
    <associate|auto-2|<tuple|2|1>>
    <associate|auto-20|<tuple|7|?>>
    <associate|auto-3|<tuple|2.1|2>>
    <associate|auto-4|<tuple|2.2|1>>
    <associate|auto-5|<tuple|2.2.1|2>>
    <associate|auto-6|<tuple|2.3|2>>
    <associate|auto-7|<tuple|2.3.1|2>>
    <associate|auto-8|<tuple|2.3.2|?>>
    <associate|auto-9|<tuple|3|?>>
    <associate|defn-AEAD|<tuple|?|?>>
    <associate|defn-aead-adv|<tuple|?|?>>
    <associate|defn-cdh|<tuple|?|?>>
    <associate|defn-ddh|<tuple|?|?>>
    <associate|defn-gdh-assumption|<tuple|?|?>>
    <associate|defn-gdh-solver|<tuple|?|?>>
    <associate|defn-orig-adv|<tuple|?|?>>
    <associate|harv_ref-ACMP10-5|<tuple|?|?>>
    <associate|harv_ref-CaKr01-1|<tuple|?|?>>
    <associate|harv_ref-GBNM11-1|<tuple|?|?>>
    <associate|harv_ref-KPW13-1|<tuple|?|?>>
    <associate|sect-comp-sec|<tuple|5|2>>
    <associate|sect-gke|<tuple|?|?>>
    <associate|sect-np1sec-in-pcl|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-pclize|<tuple|4|2>>
    <associate|sect-tca|<tuple|?|?>>
    <associate|sect-tca-sec|<tuple|3|2>>
    <associate|sect-tdh|<tuple|?|?>>
    <associate|sect-tdh-sec|<tuple|?|1>>
    <associate|tabl-tdh-protocol|<tuple|1|?>>
    <associate|thrm-np1sec-acce|<tuple|?|?>>
    <associate|thrm-np1sec-gke|<tuple|?|?>>
    <associate|thrm-np1sec-p2p-sec|<tuple|?|?>>
  </collection>
</references>
