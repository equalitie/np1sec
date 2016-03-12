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

  The sketch of the Sketch goes as follows, Section <reference|sect-tdh>
  deals with security of TDH namely its deniability. The authentication of
  TDH will be proven as parte of AKE security proof. We also prove the TDH
  protocol as a 2-party secure AKE in model presented in <cite|AMP10>.
  Section <reference|sect-GKE> prove the security properties of the group key
  exchange protocol. \ Section <reference|sect-tca-sec> we give proof of the
  security properties of TCA.

  <section|General Definition>

  In this section we introduce the ideas and definition we are using through
  out the proof.

  <\definition>
    <label|defn-cdh>Suppos <math|\<bbb-G\>> is a multiplicative group. Given
    arbitary <math|g,g<rsup|a>,g<rsup|b>\<in\>\<bbb-G\>>, the
    <strong|Computational Diffie-Hellman (CDH) problem> is to compute
    <math|g<rsup|a b>>.
  </definition>

  <\definition>
    <label|defn-ddh>Folliwing the notation in Definition
    <reference|defn-cdh>, Given arbitary <math|g,g<rsup|a>,g<rsup|b>,g<rsup|c>\<in\>\<bbb-G\>>,
    the <strong|Decisional Diffie-Hellman (DDH) problem> is to determine if
    <math|g<rsup|c>=g<rsup|a b>>.
  </definition>

  <\definition>
    <label|defn-gdh-assumption>Folliwing the notation in Definition
    <reference|defn-ddh>, <strong|Gap Diffie-Hellman probelm> is to compute
    <math|g<rsup|a b>> while having access to \ a DDH oracle. In other words,
    <strong|GDH assumption> \ for group <math|\<bbb-G\>> asserts that even if
    DDH is easy in <math|\<bbb-G\>>, computing <math|g<rsup|a b>> is hard.
  </definition>

  <\definition>
    <label|defn-gdh-solver>A <strong|Gap Diffie-Hellman Solver> or a
    <strong|GDH solver> <math|\<cal-S\>> for group <math|\<bbb-G\>> is a
    function <math|\<cal-S\>> defined as

    <\equation*>
      \<cal-S\>:<around*|(|g,g<rsup|a>,g<rsup|b>,\<cal-O\><rsub|DDH><rsub|>|)>\<longmapsto\>g<rsup|a
      b>
    </equation*>

    Where <math|\<cal-O\><rsub|DDH>> is a DDH oracle for group
    <math|\<bbb-G\>.>
  </definition>

  <\definition>
    We indicate <strong|the set of all possible participants> (in the
    universe) by <math|\<cal-U\>> such that <math|<around*|\||\<cal-U\>|\|>>
    = <math|N>, where each participants. Each participant is represented by a
    unique identity <math|U<rsub|i>>. Each <math|U<rsub|i>> is verifiably
    identified by a long term public key <math|LPK<rsub|i>> for which its
    posses its corresponding long term private key <math|LSK<rsub|i>>.
  </definition>

  <\definition>
    A<strong| Multi-party chat session >an ordered pair
    <math|\<cal-S\>\<assign\><around*|(|S\<nocomma\>\<nocomma\>,sid|)>>, in
    which <math|S\<subseteq\>\<cal-U\>> and <math|sid> is the unique
    \ session id. Without loss of generality we assume:

    <\equation*>
      S\<assign\><around*|{|U<rsub|1>,\<ldots\>,U<rsub|n>|}>
    </equation*>
  </definition>

  <with|font-series|bold|Definition V.2 sub session> After session
  <with|font-shape|italic|S> is established, A subset of participants
  <label|MathJax-Element-9-Frame><label|MathJax-Span-143><label|MathJax-Span-144><label|MathJax-Span-145><label|MathJax-Span-146><label|MathJax-Span-147><label|MathJax-Span-148><label|MathJax-Span-149><label|MathJax-Span-150><label|MathJax-Span-151>T<label|MathJax-Span-152>\<subset\><label|MathJax-Span-153><label|MathJax-Span-154><label|MathJax-Span-155><label|MathJax-Span-156><label|MathJax-Span-157>S
  might want to start a session in which parties in
  <label|MathJax-Element-10-Frame><label|MathJax-Span-158><label|MathJax-Span-159><label|MathJax-Span-160><label|MathJax-Span-161><label|MathJax-Span-162><label|MathJax-Span-163><label|MathJax-Span-164><label|MathJax-Span-165><label|MathJax-Span-166>T<label|MathJax-Span-167>\<setminus\><label|MathJax-Span-168><label|MathJax-Span-169><label|MathJax-Span-170><label|MathJax-Span-171><label|MathJax-Span-172>S
  are excluded (for example when those parties leave the chatroom). In such a
  setting we say <label|MathJax-Element-11-Frame><label|MathJax-Span-173><label|MathJax-Span-174><label|MathJax-Span-175><label|MathJax-Span-176><label|MathJax-Span-177>T<label|MathJax-Span-178>:=<label|MathJax-Span-179>(<label|MathJax-Span-180><label|MathJax-Span-181><label|MathJax-Span-182><label|MathJax-Span-183><label|MathJax-Span-184>T<label|MathJax-Span-185>,<label|MathJax-Span-186>s<label|MathJax-Span-187>i<label|MathJax-Span-188><label|MathJax-Span-189>d<label|MathJax-Span-190><label|MathJax-Span-191><label|MathJax-Span-192>T<label|MathJax-Span-193>)
  is a subsession of <with|font-shape|italic|S>. When there is no need to
  specify the subsession of choice, we use
  <label|MathJax-Element-12-Frame><label|MathJax-Span-194><label|MathJax-Span-195><label|MathJax-Span-196><label|MathJax-Span-197><label|MathJax-Span-198>s<label|MathJax-Span-199>p<label|MathJax-Span-200>i<label|MathJax-Span-201>d
  to refer to <label|MathJax-Element-13-Frame><label|MathJax-Span-202><label|MathJax-Span-203><label|MathJax-Span-204><label|MathJax-Span-205><label|MathJax-Span-206>s<label|MathJax-Span-207>i<label|MathJax-Span-208><label|MathJax-Span-209>d<label|MathJax-Span-210><label|MathJax-Span-211><label|MathJax-Span-212>T.

  <with|font-series|bold|Definition V.3> <with|font-shape|italic|An>
  <with|font-series|bold|authenticated group key exchange (AGKE)>
  <with|font-shape|italic|is Algorithm <label|MathJax-Element-14-Frame><label|MathJax-Span-213><label|MathJax-Span-214><label|MathJax-Span-215><label|MathJax-Span-216>\<Pi\>
  which each honest party will execute in order to communicate (by means of
  sending, receiving or computing) a cryptographic secret - namely a key -
  among the other parties of a session. By
  <label|MathJax-Element-15-Frame><label|MathJax-Span-217><label|MathJax-Span-218><label|MathJax-Span-219><label|MathJax-Span-220><label|MathJax-Span-221>\<Pi\><label|MathJax-Span-222><label|MathJax-Span-223><label|MathJax-Span-224>S<label|MathJax-Span-225><label|MathJax-Span-226><label|MathJax-Span-227>i
  (or <label|MathJax-Element-16-Frame><label|MathJax-Span-228><label|MathJax-Span-229><label|MathJax-Span-230><label|MathJax-Span-231><label|MathJax-Span-232>\<Pi\><label|MathJax-Span-233><label|MathJax-Span-234><label|MathJax-Span-235>i
  when the underlying session is understood) we are referring to an instance
  of <label|MathJax-Element-17-Frame><label|MathJax-Span-236><label|MathJax-Span-237><label|MathJax-Span-238><label|MathJax-Span-239>\<Pi\>
  which the party <label|MathJax-Element-18-Frame><label|MathJax-Span-240><label|MathJax-Span-241><label|MathJax-Span-242><label|MathJax-Span-243><label|MathJax-Span-244>U<label|MathJax-Span-245><label|MathJax-Span-246><label|MathJax-Span-247>i
  executes to achieve the collective goal. Further more we define>:

  <\itemize>
    <item><with|font-series|bold|Session id as seen by
    <label|MathJax-Element-19-Frame><label|MathJax-Span-248><label|MathJax-Span-249><label|MathJax-Span-250><label|MathJax-Span-251><label|MathJax-Span-252>U<label|MathJax-Span-253><label|MathJax-Span-254><label|MathJax-Span-255>i><with|font-shape|italic|:
    Session id <label|MathJax-Element-20-Frame><label|MathJax-Span-256><label|MathJax-Span-257><label|MathJax-Span-258><label|MathJax-Span-259><label|MathJax-Span-260>s<label|MathJax-Span-261>i<label|MathJax-Span-262>d
    will be derived during the execution of the protocol. The session id is
    computed by <label|MathJax-Element-21-Frame><label|MathJax-Span-263><label|MathJax-Span-264><label|MathJax-Span-265><label|MathJax-Span-266><label|MathJax-Span-267>\<Pi\><label|MathJax-Span-268><label|MathJax-Span-269><label|MathJax-Span-270>S<label|MathJax-Span-271><label|MathJax-Span-272><label|MathJax-Span-273>i
    (the instance of the protocol run by <label|MathJax-Element-22-Frame><label|MathJax-Span-274><label|MathJax-Span-275><label|MathJax-Span-276><label|MathJax-Span-277><label|MathJax-Span-278>U<label|MathJax-Span-279><label|MathJax-Span-280><label|MathJax-Span-281>i
    for session >S<with|font-shape|italic|) and is indicated by
    <label|MathJax-Element-23-Frame><label|MathJax-Span-282><label|MathJax-Span-283><label|MathJax-Span-284><label|MathJax-Span-285><label|MathJax-Span-286>s<label|MathJax-Span-287>i<label|MathJax-Span-288><label|MathJax-Span-289>d<label|MathJax-Span-290><label|MathJax-Span-291><label|MathJax-Span-292>S<label|MathJax-Span-293><label|MathJax-Span-294><label|MathJax-Span-295>i,
    or <label|MathJax-Element-24-Frame><label|MathJax-Span-296><label|MathJax-Span-297><label|MathJax-Span-298><label|MathJax-Span-299><label|MathJax-Span-300>s<label|MathJax-Span-301>i<label|MathJax-Span-302><label|MathJax-Span-303>d<label|MathJax-Span-304><label|MathJax-Span-305><label|MathJax-Span-306>i
    when there is no concern of confusion>

    <item><with|font-series|bold|Participant list><with|font-shape|italic|:
    <label|MathJax-Element-25-Frame><label|MathJax-Span-307><label|MathJax-Span-308><label|MathJax-Span-309><label|MathJax-Span-310><label|MathJax-Span-311>p<label|MathJax-Span-312>l<label|MathJax-Span-313>i<label|MathJax-Span-314>s<label|MathJax-Span-315><label|MathJax-Span-316>t<label|MathJax-Span-317><label|MathJax-Span-318><label|MathJax-Span-319>S<label|MathJax-Span-320><label|MathJax-Span-321><label|MathJax-Span-322>i
    is the list of participants which <label|MathJax-Element-26-Frame><label|MathJax-Span-323><label|MathJax-Span-324><label|MathJax-Span-325><label|MathJax-Span-326><label|MathJax-Span-327>U<label|MathJax-Span-328><label|MathJax-Span-329><label|MathJax-Span-330>i
    believes are participating in the chat session
    >S<with|font-shape|italic|.> When there is no ambiguity in the underlying
    session, we simply use <label|MathJax-Element-27-Frame><label|MathJax-Span-331><label|MathJax-Span-332><label|MathJax-Span-333><label|MathJax-Span-334><label|MathJax-Span-335>p<label|MathJax-Span-336>l<label|MathJax-Span-337>i<label|MathJax-Span-338>s<label|MathJax-Span-339><label|MathJax-Span-340>t<label|MathJax-Span-341><label|MathJax-Span-342><label|MathJax-Span-343>i
    notation.

    <item>'<with|font-shape|italic|key id> is the serial number given to the
    P2P keys generated during the process of key exchange, is computed as
    <label|MathJax-Element-28-Frame><label|MathJax-Span-344><label|MathJax-Span-345><label|MathJax-Span-346><label|MathJax-Span-347><label|MathJax-Span-348>H<label|MathJax-Span-349>a<label|MathJax-Span-350>s<label|MathJax-Span-351>h<label|MathJax-Span-352>(<label|MathJax-Span-353><label|MathJax-Span-354>U<label|MathJax-Span-355><label|MathJax-Span-356><label|MathJax-Span-357>i<label|MathJax-Span-358><label|MathJax-Span-359><label|MathJax-Span-360>\|<label|MathJax-Span-361><label|MathJax-Span-362>y<label|MathJax-Span-363><label|MathJax-Span-364><label|MathJax-Span-365>i<label|MathJax-Span-366><label|MathJax-Span-367><label|MathJax-Span-368>\|<label|MathJax-Span-369><label|MathJax-Span-370>U<label|MathJax-Span-371><label|MathJax-Span-372><label|MathJax-Span-373>j<label|MathJax-Span-374><label|MathJax-Span-375><label|MathJax-Span-376>\|<label|MathJax-Span-377><label|MathJax-Span-378>y<label|MathJax-Span-379><label|MathJax-Span-380><label|MathJax-Span-381>j<label|MathJax-Span-382>).

    <item><with|font-series|bold|Ephemeral key list><with|font-shape|italic|:
    <label|MathJax-Element-29-Frame><label|MathJax-Span-383><label|MathJax-Span-384><label|MathJax-Span-385><label|MathJax-Span-386><label|MathJax-Span-387>k<label|MathJax-Span-388>l<label|MathJax-Span-389>i<label|MathJax-Span-390>s<label|MathJax-Span-391><label|MathJax-Span-392>t<label|MathJax-Span-393><label|MathJax-Span-394><label|MathJax-Span-395>S<label|MathJax-Span-396><label|MathJax-Span-397><label|MathJax-Span-398>i
    is the list of ephemeral public key <label|MathJax-Element-30-Frame><label|MathJax-Span-399><label|MathJax-Span-400><label|MathJax-Span-401><label|MathJax-Span-402><label|MathJax-Span-403><label|MathJax-Span-404>y<label|MathJax-Span-405><label|MathJax-Span-406><label|MathJax-Span-407>j<label|MathJax-Span-408>=<label|MathJax-Span-409><label|MathJax-Span-410>g<label|MathJax-Span-411><label|MathJax-Span-412><label|MathJax-Span-413><label|MathJax-Span-414><label|MathJax-Span-415><label|MathJax-Span-416>x<label|MathJax-Span-417><label|MathJax-Span-418><label|MathJax-Span-419>j's
    of all participants which <label|MathJax-Element-31-Frame><label|MathJax-Span-420><label|MathJax-Span-421><label|MathJax-Span-422><label|MathJax-Span-423><label|MathJax-Span-424>U<label|MathJax-Span-425><label|MathJax-Span-426><label|MathJax-Span-427>i
    believes they are using in the chat session >S<with|font-shape|italic|.>
    When there is no ambiguity in the underlying session, we simply use
    <label|MathJax-Element-32-Frame><label|MathJax-Span-428><label|MathJax-Span-429><label|MathJax-Span-430><label|MathJax-Span-431><label|MathJax-Span-432>k<label|MathJax-Span-433>l<label|MathJax-Span-434>i<label|MathJax-Span-435>s<label|MathJax-Span-436><label|MathJax-Span-437>t<label|MathJax-Span-438><label|MathJax-Span-439><label|MathJax-Span-440>i
    notation instead. We use the notaion of
    <label|MathJax-Element-33-Frame><label|MathJax-Span-441><label|MathJax-Span-442><label|MathJax-Span-443><label|MathJax-Span-444><label|MathJax-Span-445>p<label|MathJax-Span-446>l<label|MathJax-Span-447>i<label|MathJax-Span-448>s<label|MathJax-Span-449><label|MathJax-Span-450>t<label|MathJax-Span-451><label|MathJax-Span-452><label|MathJax-Span-453>i<label|MathJax-Span-454><label|MathJax-Span-455><label|MathJax-Span-456>\|<label|MathJax-Span-457>k<label|MathJax-Span-458>l<label|MathJax-Span-459>i<label|MathJax-Span-460>s<label|MathJax-Span-461><label|MathJax-Span-462>t<label|MathJax-Span-463><label|MathJax-Span-464><label|MathJax-Span-465>i
    to represent ordered concatenation of
    <label|MathJax-Element-34-Frame><label|MathJax-Span-466><label|MathJax-Span-467><label|MathJax-Span-468><label|MathJax-Span-469><label|MathJax-Span-470><label|MathJax-Span-471>U<label|MathJax-Span-472><label|MathJax-Span-473><label|MathJax-Span-474>i<label|MathJax-Span-475><label|MathJax-Span-476><label|MathJax-Span-477>\|<label|MathJax-Span-478><label|MathJax-Span-479>y<label|MathJax-Span-480><label|MathJax-Span-481><label|MathJax-Span-482>i
    pairs as in <label|MathJax-Element-35-Frame><label|MathJax-Span-483><label|MathJax-Span-484><label|MathJax-Span-485><label|MathJax-Span-486><label|MathJax-Span-487><label|MathJax-Span-488>U<label|MathJax-Span-489><label|MathJax-Span-490><label|MathJax-Span-491>1<label|MathJax-Span-492><label|MathJax-Span-493><label|MathJax-Span-494>\|<label|MathJax-Span-495><label|MathJax-Span-496>y<label|MathJax-Span-497><label|MathJax-Span-498><label|MathJax-Span-499>1<label|MathJax-Span-500><label|MathJax-Span-501><label|MathJax-Span-502>\|<label|MathJax-Span-503>...<label|MathJax-Span-504><label|MathJax-Span-505><label|MathJax-Span-506>\|<label|MathJax-Span-507><label|MathJax-Span-508>U<label|MathJax-Span-509><label|MathJax-Span-510><label|MathJax-Span-511>n<label|MathJax-Span-512><label|MathJax-Span-513><label|MathJax-Span-514>\|<label|MathJax-Span-515><label|MathJax-Span-516>y<label|MathJax-Span-517><label|MathJax-Span-518><label|MathJax-Span-519>n.
    The order is assumed to be computable by all participants
    (lexicographically ordered using long term public key of participants,
    for example).

    <item><with|font-series|bold|Session key of
    <label|MathJax-Element-36-Frame><label|MathJax-Span-520><label|MathJax-Span-521><label|MathJax-Span-522><label|MathJax-Span-523><label|MathJax-Span-524>\<Pi\><label|MathJax-Span-525><label|MathJax-Span-526><label|MathJax-Span-527>S<label|MathJax-Span-528><label|MathJax-Span-529><label|MathJax-Span-530>j
    as seen by <label|MathJax-Element-37-Frame><label|MathJax-Span-531><label|MathJax-Span-532><label|MathJax-Span-533><label|MathJax-Span-534><label|MathJax-Span-535>U<label|MathJax-Span-536><label|MathJax-Span-537><label|MathJax-Span-538>i><with|font-shape|italic|:
    <label|MathJax-Element-38-Frame><label|MathJax-Span-539><label|MathJax-Span-540><label|MathJax-Span-541><label|MathJax-Span-542><label|MathJax-Span-543>s<label|MathJax-Span-544><label|MathJax-Span-545>k<label|MathJax-Span-546><label|MathJax-Span-547><label|MathJax-Span-548>S<label|MathJax-Span-549><label|MathJax-Span-550><label|MathJax-Span-551>i
    (or <label|MathJax-Element-39-Frame><label|MathJax-Span-552><label|MathJax-Span-553><label|MathJax-Span-554><label|MathJax-Span-555><label|MathJax-Span-556>s<label|MathJax-Span-557><label|MathJax-Span-558>k<label|MathJax-Span-559><label|MathJax-Span-560><label|MathJax-Span-561>i)
    is the session key of session >S<with|font-shape|italic| as computed by
    <label|MathJax-Element-40-Frame><label|MathJax-Span-562><label|MathJax-Span-563><label|MathJax-Span-564><label|MathJax-Span-565><label|MathJax-Span-566>\<Pi\><label|MathJax-Span-567><label|MathJax-Span-568><label|MathJax-Span-569>i.
    It represents the cryptographic secret computed by AGKE, it can be a set
    of secrets. The essential defining factor is that it should become common
    knowledge for the session participants at the end of AGKE execution.
    Similarly we define <label|MathJax-Element-41-Frame><label|MathJax-Span-570><label|MathJax-Span-571><label|MathJax-Span-572><label|MathJax-Span-573><label|MathJax-Span-574>s<label|MathJax-Span-575>u<label|MathJax-Span-576>b<label|MathJax-Span-577><label|MathJax-Span-578>k<label|MathJax-Span-579><label|MathJax-Span-580><label|MathJax-Span-581>i
    to represent the subsession key>

    <item><with|font-series|bold|Accepted state><with|font-shape|italic|: A
    party enters the accepted state if it has computed
    <label|MathJax-Element-42-Frame><label|MathJax-Span-582><label|MathJax-Span-583><label|MathJax-Span-584><label|MathJax-Span-585><label|MathJax-Span-586>s<label|MathJax-Span-587><label|MathJax-Span-588>k<label|MathJax-Span-589><label|MathJax-Span-590><label|MathJax-Span-591>S<label|MathJax-Span-592><label|MathJax-Span-593><label|MathJax-Span-594>i
    and has detected no errors in the protocol.>

    <item><with|font-series|bold|Partnered
    instances><with|font-shape|italic|: Two instances
    <label|MathJax-Element-43-Frame><label|MathJax-Span-595><label|MathJax-Span-596><label|MathJax-Span-597><label|MathJax-Span-598><label|MathJax-Span-599>\<Pi\><label|MathJax-Span-600><label|MathJax-Span-601><label|MathJax-Span-602>S<label|MathJax-Span-603><label|MathJax-Span-604><label|MathJax-Span-605>i
    and <label|MathJax-Element-44-Frame><label|MathJax-Span-606><label|MathJax-Span-607><label|MathJax-Span-608><label|MathJax-Span-609><label|MathJax-Span-610>\<Pi\><label|MathJax-Span-611><label|MathJax-Span-612><label|MathJax-Span-613>S<label|MathJax-Span-614><label|MathJax-Span-615><label|MathJax-Span-616>j
    are considered partnered if and only if both instances have accepted
    <label|MathJax-Element-45-Frame><label|MathJax-Span-617><label|MathJax-Span-618><label|MathJax-Span-619><label|MathJax-Span-620><label|MathJax-Span-621>s<label|MathJax-Span-622>i<label|MathJax-Span-623><label|MathJax-Span-624>d<label|MathJax-Span-625><label|MathJax-Span-626><label|MathJax-Span-627>i<label|MathJax-Span-628>=<label|MathJax-Span-629>s<label|MathJax-Span-630>i<label|MathJax-Span-631><label|MathJax-Span-632>d<label|MathJax-Span-633><label|MathJax-Span-634><label|MathJax-Span-635>j
    and <label|MathJax-Element-46-Frame><label|MathJax-Span-636><label|MathJax-Span-637><label|MathJax-Span-638><label|MathJax-Span-639><label|MathJax-Span-640>p<label|MathJax-Span-641>l<label|MathJax-Span-642>i<label|MathJax-Span-643>s<label|MathJax-Span-644><label|MathJax-Span-645>t<label|MathJax-Span-646><label|MathJax-Span-647><label|MathJax-Span-648>i<label|MathJax-Span-649>=<label|MathJax-Span-650>p<label|MathJax-Span-651>l<label|MathJax-Span-652>i<label|MathJax-Span-653>s<label|MathJax-Span-654><label|MathJax-Span-655>t<label|MathJax-Span-656><label|MathJax-Span-657><label|MathJax-Span-658>j.>
  </itemize>

  <\itemize>
    <item>A <with|font-series|bold|correct><with|font-shape|italic| AKGE
    algorithm is an AKGE which, when all <label|MathJax-Element-47-Frame><label|MathJax-Span-659><label|MathJax-Span-660><label|MathJax-Span-661><label|MathJax-Span-662><label|MathJax-Span-663>\<Pi\><label|MathJax-Span-664><label|MathJax-Span-665><label|MathJax-Span-666>S<label|MathJax-Span-667><label|MathJax-Span-668><label|MathJax-Span-669>i
    instances of AKE algorithm are initiated with access to a network which
    correctly forwards all messages without modification, all participants
    ultimately are partnered and all compute equal
    <label|MathJax-Element-48-Frame><label|MathJax-Span-670><label|MathJax-Span-671><label|MathJax-Span-672><label|MathJax-Span-673><label|MathJax-Span-674>s<label|MathJax-Span-675><label|MathJax-Span-676>k<label|MathJax-Span-677><label|MathJax-Span-678><label|MathJax-Span-679>S<label|MathJax-Span-680><label|MathJax-Span-681><label|MathJax-Span-682>i's>.
  </itemize>

  When underlying session are not considered we may omit the super script
  <label|MathJax-Element-49-Frame><label|MathJax-Span-683><label|MathJax-Span-684><label|MathJax-Span-685><label|MathJax-Span-686><label|MathJax-Span-687>_<label|MathJax-Span-688><label|MathJax-Span-689><label|MathJax-Span-690>S
  from all above notations.

  <section|Adversarial Power>

  We will re-use these definitions to demonstrate similar routes for other
  adversaries considered by the threat models in later sections.

  <subsection|Adversarial power for AKE>

  The following set of functions model the AKE adversarial threats. The
  adversary for the authenticated key exchange can mount an attack through a
  sequence of call to the functions, outlined below. The limitation on the
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
    if it has accepted (as defined in Definition III.3).

    <item><with|font-series|bold|RevealSK>:
    <label|MathJax-Element-73-Frame><label|MathJax-Span-946><label|MathJax-Span-947><label|MathJax-Span-948><label|MathJax-Span-949><label|MathJax-Span-950>\<Pi\><label|MathJax-Span-951><label|MathJax-Span-952><label|MathJax-Span-953>S<label|MathJax-Span-954><label|MathJax-Span-955><label|MathJax-Span-956>i
    gives the <label|MathJax-Element-74-Frame><label|MathJax-Span-957><label|MathJax-Span-958><label|MathJax-Span-959><label|MathJax-Span-960><label|MathJax-Span-961>s<label|MathJax-Span-962>u<label|MathJax-Span-963>b<label|MathJax-Span-964><label|MathJax-Span-965>k<label|MathJax-Span-966><label|MathJax-Span-967><label|MathJax-Span-968>T<label|MathJax-Span-969><label|MathJax-Span-970><label|MathJax-Span-971>i
    to <label|MathJax-Element-75-Frame><label|MathJax-Span-972><label|MathJax-Span-973><label|MathJax-Span-974><label|MathJax-Span-975><label|MathJax-Span-976><label|MathJax-Span-977><label|MathJax-Span-978><label|MathJax-Span-979><label|MathJax-Span-980>A<label|MathJax-Span-981><label|MathJax-Span-982><label|MathJax-Span-983>a
    if it has been computed for subsession <with|font-shape|italic|T>.

    <item>RevealPeer(<math|\<Pi\><rsub|i><rsup|S>>,<math|U<rsub|j>>): When
    the <verbatim|<math|\<cal-A\>>> call this function, it will be provided
    with the <math|p2p> key <math|k<rsub|i,j><rsup|S>>, if it is already
    computed.

    <item><with|font-series|bold|Corrupt(<label|MathJax-Element-76-Frame><label|MathJax-Span-984><label|MathJax-Span-985><label|MathJax-Span-986><label|MathJax-Span-987><label|MathJax-Span-988>U<label|MathJax-Span-989><label|MathJax-Span-990><label|MathJax-Span-991>i)>:
    <label|MathJax-Element-77-Frame><label|MathJax-Span-992><label|MathJax-Span-993><label|MathJax-Span-994><label|MathJax-Span-995><label|MathJax-Span-996>U<label|MathJax-Span-997><label|MathJax-Span-998><label|MathJax-Span-999>i
    gives its long term secret key to <label|MathJax-Element-78-Frame><label|MathJax-Span-1000><label|MathJax-Span-1001><label|MathJax-Span-1002><label|MathJax-Span-1003><label|MathJax-Span-1004><label|MathJax-Span-1005><label|MathJax-Span-1006><label|MathJax-Span-1007><label|MathJax-Span-1008>A<label|MathJax-Span-1009><label|MathJax-Span-1010><label|MathJax-Span-1011>a
    (but not the session key).
  </itemize>

  <\definition>
    <strong|AKE-Security of P2P Keys>, Let <math|\<cal-P\>> <math|GKE+P >
    protocol and <math|b> a uniformly chosen bit. Adversary
    <math|\<cal-A\><rsub|p2p>> is allowed to invoke all adversarial queries.
    At some point the Adversary runs <math|TestPeer<around*|(|\<Pi\><rsub|i><rsup|S>\<nocomma\>,U<rsub|j>|)>>
    for some fresh instance,User pair <math|<around*|(|\<Pi\><rsub|i><rsup|S>\<nocomma\>,U<rsub|j>|)>>
    which remains fresh. <math|\<cal-A\><rsub|p2p>> is allowed to continue
    the adversarial queries provided the test pair remains fresh. Finally
    <math|\<cal-A\><rsub|p2p>> outputs a bit <math|b<rprime|'>>. The
    adversarial advantage is defined as

    <\equation*>
      Adv<rsub|\<cal-A\><rsub|p2p>><around*|(|\<cal-P\>|)>\<assign\><around*|\||2Pr<around*|(|b<rprime|'>=b|)>-1|\|>
    </equation*>

    We say the <math|\<cal-P\>> is secure if the advantage is negligible.
  </definition>

  \;

  <section|Security of Triple Diffie-Hellman Authentication><label|sect-tdh>

  <subsection|The Triple Diffie-Hellman Protocol>

  <\float|float|tbh>
    <\big-table|<tabular|<tformat|<table|<row|<cell|Round
    1>|<cell|<math|A\<rightarrow\>B: <rprime|''>A<rprime|''>,g<rsup|a>>>|<cell|<math|B\<rightarrow\>A:<rprime|''>B<rprime|''>,g<rsup|b>>>>|<row|<cell|Key
    Computation>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|b>|)><rsup|A>\|<around*|(|g<rsup|B>|)><rsup|a>\|<around*|(|g<rsup|b>|)><rsup|a>|)>>>|<cell|<math|k\<leftarrow\>H<around*|(|<around*|(|g<rsup|A>|)><rsup|b>\|<around*|(|g<rsup|a>|)><rsup|B>\|<around*|(|g<rsup|a>|)><rsup|b>|)>>>>|<row|<cell|Round
    2>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,A|)>|)>>>|<cell|<math|Enc<rsub|k><around*|(|H<around*|(|k,B|)>|)>>>>>>>>
      Triple Diffie-Hellman protocol<label|tabl-tdh-protocol>
    </big-table>
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

    Intuitively, when <math|\<cal-A\><rsub|deny>> sends <math|g<rsup|a>> to
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>>,
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>><math|> inquire
    <math|\<cal-A\><rsub|deny>> for <math|a>, in this way
    <math|<with|math-font|cal|>\<cal-S\><rsub|deny>> also can compute the
    same key <math|k> by asking <math|\<cal-A\><rsub|deny><rsup|\<ast\>>>. If
    <math|\<cal-A\><rsub|deny>> has chosen
    <math|g<rsup|a>\<in\>Tr<around*|(|B|)>> or just chosen a random element
    of the group without knowing its DLP, then <math|\<cal-S\><rsub|deny>>
    will choose a random exponent <math|a<rprime|'>> and computes the key
    <math|k> based on that and computes the confirmation value using
    <math|k>. Due to hardship of CDH this value is indistinguishable from a
    <math|k> generated by <math|B>

    Now we suppose that the TDH is not deniable and we build a solver for
    CDH. First we note that if <math|\<cal-A\><rsub|deny>> engages in an
    honest interaction with <math|B> there is no way that <math|\<cal-J\>>
    can distinguish between the <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>>
    and <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>>. As
    <math|\<cal-A\><rsub|deny>> is able to generate the very exact transcript
    without help of <math|B>. Therefore, logically, the only possibility for
    <math|\<cal-J\>> to distinguish <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>>
    and <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>> is when
    <math|\<cal-A\><rsub|deny>> present <math|\<cal-J\>> with a transcript
    that <math|\<cal-A\><rsub|deny>> is not able to generate zirself. The
    only variable that <math|\<cal-A\><rsub|deny>> has control over in the
    course of the exchange is <math|g<rsup|a>> and therefore the only way
    <math|\<cal-A\><rsub|deny>> is able to claim that ze were unable to
    generate the geneuine \ <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>>
    is by submiting <math|g<rsup|a>> which zirself does not know about its
    <math|a> exponent.

    In such case, assuming the undeniability of TDH we have an
    <math|\<varepsilon\>> such that

    <\equation*>
      <math|>max<rsub|all \<cal-J\>><rsub|>\|2Pr(Output<around*|(|\<cal-J\>,Aux|)>
      = b) -1\|\<gtr\>\<varepsilon\>
    </equation*>

    The solver <math|\<cal-A\><rsub|CDH>> receives a triple
    <math|<around*|(|g,g<rsup|a>,g<rsup|b>|)>> and should compute
    <math|g<rsup|a b>>. To that end, assuming long term identiy
    <math|g<rsup|A>> for some <math|\<cal-A\><rsub|deny>>, ze engages ,in a
    TDH key exchange with a hypothetical automated party
    <math|\<cal-A\><rsup|\<ast\>>> with long term private key <math|B> who
    generates <math|g<rsup|b>> as the ephemeral key as well.
    <math|\<cal-A\><rsub|CDH>>, then toss a coin and based on the result it
    either choose a random <math|a<rprime|'>> and compute
    <math|g<rprime|'>=g<rsup|a<rprime|'>>> or set
    <math|g<rprime|'>=g<rsup|a>,>then ze submits
    <math|h<rsub|0>=H<around*|(|g<rsup|b><rsup|
    A>\<nocomma\>,g<rprime|'><rsup|B>,g<rsup|b a<rprime|'>>|)>> along side
    with <math|<around*|(|g<rsup|B>,g<rsup|b>|)>> to the <math|\<cal-J\>> as
    a proof of engagement with <math|\<cal-A\><rsup|\<ast\>>>. Due to
    undeniability assumption

    <\equation*>
      Output<around*|(|\<cal-J\>,Aux|)><around*|(|h<rsub|0>,<around*|(|A,g<rsup|a>,B,g<rsup|b>|)>|)>=b
    </equation*>

    with significant probablity as means <math|\<cal-J\>> is able to
    distinguish <math|T<around*|(|\<cal-A\><rsub|deny><around*|(|Aux|)>|)>>
    and <math|T<around*|(|\<cal-S\><rsub|deny><around*|(|Aux|)>|)>> with high
    probablity. Therefore <math|\<cal-J\>> is able to decide if:

    <\equation*>
      h<rsub|0><long-arrow|\<rubber-equal\>|?>\<nocomma\>H<around*|(|g<rsup|b
      A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>,<around*|(|g<rsup|a>|)><rsup|b>|)>
    </equation*>

    Because <math|H> is a random oracle the only way that the judge is able
    to distinguish the second value from the real value is to have knowledge
    about the exact pre-image: <math|g<rsup|b
    A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>,<around*|(|g<rsup|a>|)><rsup|b>>.
    Using the information in the transcript <math|\<cal-J\>> can compute
    <math|g<rsup|b A>\<nocomma\>,<around*|(|g<rsup|a >|)><rsup|B>>, but still
    has to compute <math|g<rsup|ab>> using <math|g<rsup|a>> and
    <math|g<rsup|b>> with high probablity without knowing <math|a> or
    <math|b>, at this point <math|\<cal-A\><rsub|CDH>> is publishing the
    value of <math|g<rsup|a b>>.

    \;
  </proof>

  <subsection|Security of TDH as a two party Authenticate Key Exchange>

  In this section we prove that TDH is a secure two-party authenticated key
  exchange. we do so in the AKE security model proposed in
  <math|<cite|Ma09>>. This is because (n+1)Sec key exchange protocol is a
  varient of the protocol proposed in <cite|AMP10>, which is designed to
  satisifies all three AKE models proposed in <cite|Ma09> and <cite|AMP10>.
  Furthermore, based on the security properties required from (n+1)Sec as a
  secure multiparty chat protocol, we beleive these models provide adequite
  security for real world threat scenarios.

  <\theorem>
    If the GDH problem is hard in <math|\<bbb-G\>>, then TDH protocol
    explained in Table <reference|tabl-tdh-protocol>, is secure in AKE model
    with advantage of the adversary is bounded by

    <\equation*>
      Adv<rsub|\<cal-A\><rsub|p2p><around*|(|k|)>\<leqslant\>\<cal-O\><around*|(|q<rsup|2>|)>>/Q
    </equation*>
  </theorem>

  Where <math|q> is the maximum number of queries by the adversary\ 

  <\proof>
    Suppose that <math|k<rsub|test>=H<around*|(|<around*|(|g<rsup|b>|)><rsup|A>\|<around*|(|g<rsup|B>|)><rsup|a>\|<around*|(|g<rsup|b>|)><rsup|a>|)>>.
    Assuming that <math|H> is a PRF (SHA-256 in case of (n+1)sec, the only
    way that adveresy <math|\<cal-A\><rsub|p2p>> can distinguish
    <math|k<rsub|test>> from a random value <math|k<rprime|'>> is to compute
    all element of triplet <math|<around*|(|g<rsup|b>|)><rsup|A>\<nocomma\>,<around*|(|g<rsup|B>|)><rsup|a>,<around*|(|g<rsup|b>|)><rsup|a>>.

    We show how to construct a GDH solver using an <math|\<cal-A\><rsub|p2p>>
    who can compute all three above. Assuming that the test session is Fresh,
    then the adversay can not corrupt neither <math|A> or <math|B> and can
    request session reveal on the test session. Therefore it does not have
    neither access to <math|a> or <math|b>.

    Now suppose simulator <math|\<cal-S\>>, has access to the Adversary
    <math|\<cal-A\>> oracle which is able to compute the triple diffie
    hellman inside the paranthesis. <math|\<cal-S\>> need to solve
    <math|g<rsup|a b>> for a given <math|g<rsup|a>> and <math|g<rsup|b>>. As
    such it generates a transcript to set up a session between <math|A> and
    <math|B> while inserting <math|g<rsup|a>> and <math|g<rsup|b>> as
    exchanged keys.

    Assuming that the adversary can compute the last token which is the
    solution to CDH.

    \ 
  </proof>

  <\theorem>
    If the GDH problem is hard in <math|\<bbb-G\>>, then (n+1)sec protocol is
    secure against <math|\<cal-A\><rsub|p2p>>
    adversary.<label|thrm-np1sec-p2p-sec>
  </theorem>

  <\proof>
    We argue that the AKE security for the (n+1)Sec <math|p2p> keys follows
    similarly to from the proof of Theorem 8 <cite|AMP10> which proves the
    security of BD+P protocol.\ 

    In fact we follow the same sequence of games for games <math|G<rsub|0>>
    and <math|G<rsub|1>>.\ 

    For the game <math|G<rsub|2>> we note that contrary to mBP+P which signs
    the second round message with <math|LPK<rsub|i>> for authentication,
    adversary has two ways to forge the authentication and force the other
    party accept a wrong key. One is to forge the signture generated by
    ephemeral key. This basically covered by <math|G<rsub|2>>. However,
    another way is to forge the authentication token we simulate in
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
    able to impersonate <math|A> to <math|B>. Not knowing neither secret
    <math|b> or <math|LPK<rsub|i>>, the advantage of
    <math|\<cal-A\><rsub|p2p>> is bounded by its advantage in solving GDH.
    The adversary needs to solve all three GDH problems. Therefore we have:

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|2>|]>-Pr<around*|[|Win<rsub|2<rprime|'>>|]>|\|>\<less\>q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    In fact the only difference in the proof is related to <math|G<rsub|6>>.
    As <math|k<rsub|i j>> is computed as <math|H<around*|(|g<rsup|A
    b><around*|\||g<rsup|B a>|\|>g<rsup|a b>|)>>. Therefore simulator delta
    will output <math|H<rprime|'><around*|(|g<rsup|A>\|g<rsup|B>\|g<rsup|a>\|g<rsup|b>|)>>.
    However because <math|H> is a prefect PRF, this remains indistinguishble,
    unless the adversary has advantage on computing <math|g<rsup|A
    b>,g<rsup|B a>,g<rsup|a b>>.

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|6>|]>-Pr<around*|[|Win<rsub|5>|]>|\|>\<less\>q
      H<rsub|p><around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    Consequently, the overal advantage of <math|\<cal-A\><rsub|p2p>> bar its
    advantage in transition from <math|G<rsub|2>> to
    <math|G<rsub|2<rprime|'>>>, is smaller than their advantage in the
    original mBD+P protocol:

    <\equation*>
      Adv<rsup|p2p><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>\<less\>Adv<rsup|p2p><rsub|mBD+P>*<around*|(|\<kappa\>|)>+q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    This proves that <math|Adv<rsup|p2p><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>>
    is asymtotically the same as <math|Adv<rsup|p2p><rsub|mBD+P><around*|(|\<kappa\>|)>>.

    \;
  </proof>

  <section|Security of (n+1)sec authenticated group key
  exchange><label|sect-gke>

  In this section we prove the security of (n+1)sec group key exchange in the
  proposed adversarial model. Because the key exchange is essentially FAGKE
  with only difference is that the traditional DH key exchange replaced by
  TDH, we prove the security of (n+1)sec GKE based on the security of FAKE.

  <subsection|Security of GKE>

  We recall that the GKE protocol in (n+1)Sec is essentially the same as
  FAGKE protocol except that in <math|>(n+1)Sec we have:

  <\equation*>
    k<rsub|i,i+1>=H<around*|(|g<rsup|LS<rsub|i>x<rsub|i+1>>,g<rsup|LS<rsub|i+1>x<rsub|i>>\<nocomma\>,g<rsup|x<rsub|i>x<rsub|i+1>>|)>
  </equation*>

  Where as in FAGKE we have:

  <\equation*>
    k<rsub|i,i+1>=g<rsup|x<rsub|i>x<rsub|i+1>>
  </equation*>

  Therefore, to prove the that <math|<around*|(|n+1|)>>Sec we need to prove
  Theorem <reference|thrm-np1sec-gke>:

  <\theorem>
    <label|thrm-np1sec-gke>If \ GDH problem is hard then (n+1)sec key
    exchange provides AKE-security of group keys.
  </theorem>

  <\proof>
    We argue that the AKE security for the (n+1)Sec group key follows
    similarly to from the proof of Theorem 7 <cite|AMP10> which proves the
    security of BD+P protocol.

    In fact we follow the same sequence of games for games <math|G<rsub|0>>
    and <math|G<rsub|1>>.\ 

    Similar to the case of <math|p2p> argued in Theorem
    <reference|thrm-np1sec-p2p-sec>, we need to expand game <math|G<rsub|2>>
    into two games of <math|G<rsub|2>> and <math|G<rsub|2><rprime|'>> to
    account both for the forgery of the signature and the TDH tocken. With
    the transitional advantage of

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|2>|]>-Pr<around*|[|Win<rsub|2<rprime|'>>|]>|\|>\<less\>q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    We proceesd similarly with game <math|G<rsub|3>>. The difference in the
    proof is related to <math|G<rsub|4>>. \<Delta\> responds with
    <math|g<rsup|a<rsub|>>> and <math|g<rsup|b>> from the values of the GDH
    challenge. In this game instead of computing <math|z<rprime|'><rsub|i >>
    as <math|H<around*|(|H<around*|(|g<rsup|A b><around*|\||g<rsup|B
    a>|\|>g<rsup|a b>|)>,sid|)>>, simulator \<Delta\> will output
    <math|H<rprime|'><around*|(|g<rsup|A>\|g<rsup|B>\|g<rsup|a>\|g<rsup|b>|)>>.
    However because <math|H> is a prefect PRF, this remains indistinguishble,
    unless the adversary has advantage on computing <math|g<rsup|A
    b>,g<rsup|B a>,g<rsup|a b>>. So we have

    <\equation*>
      <around*|\||Pr<around*|[|Win<rsub|6>|]>-Pr<around*|[|Win<rsub|5>|]>|\|>\<less\>q
      H<rsub|p><around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    \;

    The remaining argument for game <math|G<rsub|4>> is the same as
    <math|mBD+P> proof.\ 

    Consequently, the overal advantage of
    <math|\<cal-A\><rsup|ake-g><rsub|<around*|(|n+1|)>sec>> bar its advantage
    in transition from <math|G<rsub|2>> to <math|G<rsub|2<rprime|'>>>, is
    smaller than their advantage in the original mBD+P protocol:

    <\equation*>
      Adv<rsup|ake-g><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>\<less\>Adv<rsup|ake-g><rsub|mBD+P>*<around*|(|\<kappa\>|)>+q
      <around*|(|Succ<rsup|GDH><rsub|\<bbb-G\>><rsup|><around*|(|\<kappa\>|)>|)><rsup|3>
    </equation*>

    This proves that <math|Adv<rsup|ake-g><rsub|<around*|(|n+1|)>sec><around*|(|\<kappa\>|)>>
    is asymtotically the same as <math|Adv<rsup|ake-g><rsub|mBD+P><around*|(|\<kappa\>|)>>.

    \;
  </proof>

  <section|Security of Transcript Consistency Assurance>

  <label|sect-tca>

  \;
</body>

<\references>
  <\collection>
    <associate|MathJax-Element-1-Frame|<tuple|5|?>>
    <associate|MathJax-Element-10-Frame|<tuple|6|?>>
    <associate|MathJax-Element-11-Frame|<tuple|6|?>>
    <associate|MathJax-Element-12-Frame|<tuple|6|?>>
    <associate|MathJax-Element-13-Frame|<tuple|6|?>>
    <associate|MathJax-Element-14-Frame|<tuple|6|?>>
    <associate|MathJax-Element-15-Frame|<tuple|6|?>>
    <associate|MathJax-Element-16-Frame|<tuple|6|?>>
    <associate|MathJax-Element-17-Frame|<tuple|6|?>>
    <associate|MathJax-Element-18-Frame|<tuple|6|?>>
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
    <associate|MathJax-Element-62-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-63-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-64-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-65-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-66-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-67-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-68-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-69-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-7-Frame|<tuple|6|?>>
    <associate|MathJax-Element-70-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-71-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-72-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-73-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-74-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-75-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-76-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-77-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-78-Frame|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Element-8-Frame|<tuple|6|?>>
    <associate|MathJax-Element-9-Frame|<tuple|6|?>>
    <associate|MathJax-Span-1|<tuple|5|?>>
    <associate|MathJax-Span-10|<tuple|5|?>>
    <associate|MathJax-Span-100|<tuple|6|?>>
    <associate|MathJax-Span-1000|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1001|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1002|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1003|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1004|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1005|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1006|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1007|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1008|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1009|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-101|<tuple|6|?>>
    <associate|MathJax-Span-1010|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-1011|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
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
    <associate|MathJax-Span-143|<tuple|6|?>>
    <associate|MathJax-Span-144|<tuple|6|?>>
    <associate|MathJax-Span-145|<tuple|6|?>>
    <associate|MathJax-Span-146|<tuple|6|?>>
    <associate|MathJax-Span-147|<tuple|6|?>>
    <associate|MathJax-Span-148|<tuple|6|?>>
    <associate|MathJax-Span-149|<tuple|6|?>>
    <associate|MathJax-Span-15|<tuple|5|?>>
    <associate|MathJax-Span-150|<tuple|6|?>>
    <associate|MathJax-Span-151|<tuple|6|?>>
    <associate|MathJax-Span-152|<tuple|6|?>>
    <associate|MathJax-Span-153|<tuple|6|?>>
    <associate|MathJax-Span-154|<tuple|6|?>>
    <associate|MathJax-Span-155|<tuple|6|?>>
    <associate|MathJax-Span-156|<tuple|6|?>>
    <associate|MathJax-Span-157|<tuple|6|?>>
    <associate|MathJax-Span-158|<tuple|6|?>>
    <associate|MathJax-Span-159|<tuple|6|?>>
    <associate|MathJax-Span-16|<tuple|5|?>>
    <associate|MathJax-Span-160|<tuple|6|?>>
    <associate|MathJax-Span-161|<tuple|6|?>>
    <associate|MathJax-Span-162|<tuple|6|?>>
    <associate|MathJax-Span-163|<tuple|6|?>>
    <associate|MathJax-Span-164|<tuple|6|?>>
    <associate|MathJax-Span-165|<tuple|6|?>>
    <associate|MathJax-Span-166|<tuple|6|?>>
    <associate|MathJax-Span-167|<tuple|6|?>>
    <associate|MathJax-Span-168|<tuple|6|?>>
    <associate|MathJax-Span-169|<tuple|6|?>>
    <associate|MathJax-Span-17|<tuple|5|?>>
    <associate|MathJax-Span-170|<tuple|6|?>>
    <associate|MathJax-Span-171|<tuple|6|?>>
    <associate|MathJax-Span-172|<tuple|6|?>>
    <associate|MathJax-Span-173|<tuple|6|?>>
    <associate|MathJax-Span-174|<tuple|6|?>>
    <associate|MathJax-Span-175|<tuple|6|?>>
    <associate|MathJax-Span-176|<tuple|6|?>>
    <associate|MathJax-Span-177|<tuple|6|?>>
    <associate|MathJax-Span-178|<tuple|6|?>>
    <associate|MathJax-Span-179|<tuple|6|?>>
    <associate|MathJax-Span-18|<tuple|5|?>>
    <associate|MathJax-Span-180|<tuple|6|?>>
    <associate|MathJax-Span-181|<tuple|6|?>>
    <associate|MathJax-Span-182|<tuple|6|?>>
    <associate|MathJax-Span-183|<tuple|6|?>>
    <associate|MathJax-Span-184|<tuple|6|?>>
    <associate|MathJax-Span-185|<tuple|6|?>>
    <associate|MathJax-Span-186|<tuple|6|?>>
    <associate|MathJax-Span-187|<tuple|6|?>>
    <associate|MathJax-Span-188|<tuple|6|?>>
    <associate|MathJax-Span-189|<tuple|6|?>>
    <associate|MathJax-Span-19|<tuple|5|?>>
    <associate|MathJax-Span-190|<tuple|6|?>>
    <associate|MathJax-Span-191|<tuple|6|?>>
    <associate|MathJax-Span-192|<tuple|6|?>>
    <associate|MathJax-Span-193|<tuple|6|?>>
    <associate|MathJax-Span-194|<tuple|6|?>>
    <associate|MathJax-Span-195|<tuple|6|?>>
    <associate|MathJax-Span-196|<tuple|6|?>>
    <associate|MathJax-Span-197|<tuple|6|?>>
    <associate|MathJax-Span-198|<tuple|6|?>>
    <associate|MathJax-Span-199|<tuple|6|?>>
    <associate|MathJax-Span-2|<tuple|5|?>>
    <associate|MathJax-Span-20|<tuple|5|?>>
    <associate|MathJax-Span-200|<tuple|6|?>>
    <associate|MathJax-Span-201|<tuple|6|?>>
    <associate|MathJax-Span-202|<tuple|6|?>>
    <associate|MathJax-Span-203|<tuple|6|?>>
    <associate|MathJax-Span-204|<tuple|6|?>>
    <associate|MathJax-Span-205|<tuple|6|?>>
    <associate|MathJax-Span-206|<tuple|6|?>>
    <associate|MathJax-Span-207|<tuple|6|?>>
    <associate|MathJax-Span-208|<tuple|6|?>>
    <associate|MathJax-Span-209|<tuple|6|?>>
    <associate|MathJax-Span-21|<tuple|5|?>>
    <associate|MathJax-Span-210|<tuple|6|?>>
    <associate|MathJax-Span-211|<tuple|6|?>>
    <associate|MathJax-Span-212|<tuple|6|?>>
    <associate|MathJax-Span-213|<tuple|6|?>>
    <associate|MathJax-Span-214|<tuple|6|?>>
    <associate|MathJax-Span-215|<tuple|6|?>>
    <associate|MathJax-Span-216|<tuple|6|?>>
    <associate|MathJax-Span-217|<tuple|6|?>>
    <associate|MathJax-Span-218|<tuple|6|?>>
    <associate|MathJax-Span-219|<tuple|6|?>>
    <associate|MathJax-Span-22|<tuple|5|?>>
    <associate|MathJax-Span-220|<tuple|6|?>>
    <associate|MathJax-Span-221|<tuple|6|?>>
    <associate|MathJax-Span-222|<tuple|6|?>>
    <associate|MathJax-Span-223|<tuple|6|?>>
    <associate|MathJax-Span-224|<tuple|6|?>>
    <associate|MathJax-Span-225|<tuple|6|?>>
    <associate|MathJax-Span-226|<tuple|6|?>>
    <associate|MathJax-Span-227|<tuple|6|?>>
    <associate|MathJax-Span-228|<tuple|6|?>>
    <associate|MathJax-Span-229|<tuple|6|?>>
    <associate|MathJax-Span-23|<tuple|5|?>>
    <associate|MathJax-Span-230|<tuple|6|?>>
    <associate|MathJax-Span-231|<tuple|6|?>>
    <associate|MathJax-Span-232|<tuple|6|?>>
    <associate|MathJax-Span-233|<tuple|6|?>>
    <associate|MathJax-Span-234|<tuple|6|?>>
    <associate|MathJax-Span-235|<tuple|6|?>>
    <associate|MathJax-Span-236|<tuple|6|?>>
    <associate|MathJax-Span-237|<tuple|6|?>>
    <associate|MathJax-Span-238|<tuple|6|?>>
    <associate|MathJax-Span-239|<tuple|6|?>>
    <associate|MathJax-Span-24|<tuple|5|?>>
    <associate|MathJax-Span-240|<tuple|6|?>>
    <associate|MathJax-Span-241|<tuple|6|?>>
    <associate|MathJax-Span-242|<tuple|6|?>>
    <associate|MathJax-Span-243|<tuple|6|?>>
    <associate|MathJax-Span-244|<tuple|6|?>>
    <associate|MathJax-Span-245|<tuple|6|?>>
    <associate|MathJax-Span-246|<tuple|6|?>>
    <associate|MathJax-Span-247|<tuple|6|?>>
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
    <associate|MathJax-Span-805|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-806|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-807|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-808|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-809|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-81|<tuple|6|?>>
    <associate|MathJax-Span-810|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-811|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-812|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-813|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-814|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-815|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-816|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-817|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-818|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-819|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-82|<tuple|6|?>>
    <associate|MathJax-Span-820|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-821|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-822|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-823|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-824|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-825|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-826|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-827|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-828|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-829|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-83|<tuple|6|?>>
    <associate|MathJax-Span-830|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-831|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-832|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-833|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-834|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-835|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-836|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-837|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-838|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-839|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-84|<tuple|6|?>>
    <associate|MathJax-Span-840|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-841|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-842|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-843|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-844|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-845|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-846|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-847|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-848|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-849|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-85|<tuple|6|?>>
    <associate|MathJax-Span-850|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-851|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-852|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-853|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-854|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-855|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-856|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-857|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-858|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-859|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-86|<tuple|6|?>>
    <associate|MathJax-Span-860|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-861|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-862|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-863|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-864|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-865|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-866|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-867|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-868|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-869|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-87|<tuple|6|?>>
    <associate|MathJax-Span-870|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-871|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-872|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-873|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-874|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-875|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-876|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-877|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-878|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-879|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-88|<tuple|6|?>>
    <associate|MathJax-Span-880|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-881|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-882|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-883|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-884|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-885|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-886|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-887|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
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
    <associate|MathJax-Span-899|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-9|<tuple|5|?>>
    <associate|MathJax-Span-90|<tuple|6|?>>
    <associate|MathJax-Span-900|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-901|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-902|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-903|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-904|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-905|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-906|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-907|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-908|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-909|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-91|<tuple|6|?>>
    <associate|MathJax-Span-910|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-911|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-912|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-913|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-914|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-915|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-916|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-917|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-918|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-919|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-92|<tuple|6|?>>
    <associate|MathJax-Span-920|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-921|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-922|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-923|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-924|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-925|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-926|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-927|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-928|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-929|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-93|<tuple|6|?>>
    <associate|MathJax-Span-930|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-931|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
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
    <associate|MathJax-Span-946|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-947|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-948|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-949|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-95|<tuple|6|?>>
    <associate|MathJax-Span-950|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-951|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-952|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-953|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-954|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-955|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-956|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-957|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-958|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-959|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-96|<tuple|6|?>>
    <associate|MathJax-Span-960|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-961|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-962|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-963|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-964|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-965|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-966|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-967|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-968|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-969|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-97|<tuple|6|?>>
    <associate|MathJax-Span-970|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-971|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-972|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-973|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-974|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-975|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-976|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-977|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-978|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-979|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-98|<tuple|6|?>>
    <associate|MathJax-Span-980|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-981|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-982|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-983|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-984|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-985|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-986|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-987|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-988|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-989|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-99|<tuple|6|?>>
    <associate|MathJax-Span-990|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-991|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-992|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-993|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-994|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-995|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-996|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-997|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-998|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|MathJax-Span-999|<tuple|<with|mode|<quote|math>|\<bullet\>>|?>>
    <associate|auto-1|<tuple|1|1>>
    <associate|auto-10|<tuple|4.1|?>>
    <associate|auto-11|<tuple|5|?>>
    <associate|auto-2|<tuple|2|1>>
    <associate|auto-3|<tuple|2.1|2>>
    <associate|auto-4|<tuple|3|1>>
    <associate|auto-5|<tuple|3.1|2>>
    <associate|auto-6|<tuple|1|2>>
    <associate|auto-7|<tuple|3.2|2>>
    <associate|auto-8|<tuple|3.3|?>>
    <associate|auto-9|<tuple|4|?>>
    <associate|defn-cdh|<tuple|1|?>>
    <associate|defn-ddh|<tuple|2|?>>
    <associate|defn-gdh-assumption|<tuple|3|?>>
    <associate|defn-gdh-solver|<tuple|4|?>>
    <associate|sect-comp-sec|<tuple|5|2>>
    <associate|sect-gke|<tuple|4|?>>
    <associate|sect-np1sec-in-pcl|<tuple|3|?|../../../.TeXmacs/texts/scratch/no_name_12.tm>>
    <associate|sect-np1sec-pclize|<tuple|4|2>>
    <associate|sect-tca|<tuple|5|?>>
    <associate|sect-tca-sec|<tuple|3|2>>
    <associate|sect-tdh|<tuple|3|?>>
    <associate|sect-tdh-sec|<tuple|3.2|1>>
    <associate|tabl-tdh-protocol|<tuple|1|?>>
    <associate|thrm-np1sec-gke|<tuple|12|?>>
    <associate|thrm-np1sec-p2p-sec|<tuple|11|?>>
  </collection>
</references>

<\auxiliary>
  <\collection>
    <\associate|bib>
      AMP10

      AMP10

      GKR06

      Ma09

      AMP10

      Ma09

      AMP10

      AMP10

      ACMP10

      ACMP10
    </associate>
    <\associate|table>
      <\tuple|normal>
        Triple Diffie-Hellman protocol
      </tuple|<pageref|auto-6>>
    </associate>
    <\associate|toc>
      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|1<space|2spc>General
      Definition> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-1><vspace|0.5fn>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|2<space|2spc>Adversarial
      Power> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-2><vspace|0.5fn>

      <with|par-left|<quote|1tab>|2.1<space|2spc>Adversarial power for AKE
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-3>>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|3<space|2spc>Security
      of Triple Diffie-Hellman Authentication>
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-4><vspace|0.5fn>

      <with|par-left|<quote|1tab>|3.1<space|2spc>The Triple Diffie-Hellman
      Protocol <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-5>>

      <with|par-left|<quote|1tab>|3.2<space|2spc>The deniablity of TDH
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-7>>

      <with|par-left|<quote|1tab>|3.3<space|2spc>Security of TDH as a two
      party Authenticate Key Exchange <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-8>>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|4<space|2spc>Security
      of (n+1)sec authenticated group key exchange>
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-9><vspace|0.5fn>

      <with|par-left|<quote|1tab>|4.1<space|2spc>Security of GKE
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-10>>

      <vspace*|1fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|5<space|2spc>Security
      of Transcript Consistency Assurance>
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-11><vspace|0.5fn>
    </associate>
  </collection>
</auxiliary>