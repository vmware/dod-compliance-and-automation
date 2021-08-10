<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cdf="http://checklists.nist.gov/xccdf/1.1">
  <xsl:template match="/">
    <html>
      <head>
        <title>
				UNCLASSIFIED
					<xsl:value-of select="cdf:Benchmark/title"/>
        </title>
      </head>
      <body>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <br/>
        <p align="center">
          <b>
            <font size="7">UNCLASSIFIED 
						</font>
          </b>
          <br/>
        </p>
        <p align="center">
          <img width="958" height="185" src="vmware.jpg"> </img>
        </p>
        <xsl:apply-templates select="cdf:Benchmark"/>
      </body>
    </html>
  </xsl:template>
  <xsl:template match="cdf:Benchmark">
&#160;
            <br/>
    <br/>
    <p align="center">
      <b>
        <font size="7">
          <xsl:value-of select="cdf:title"/>
        </font>
      </b>
      <br/>
    </p>
    <p align="center">
      <b>
        <font size="7">
          <xsl:if test="cdf:status='draft'">
                                     DRAFT
                                <br/>
          </xsl:if>
        </font>
      </b>
    </p>
    <p align="center">
      <b>
        <font size="7">Version:&#160;<xsl:value-of select="cdf:version"/>
        </font>
      </b>
      <br/>
    </p>
    <p align="center">
      <b>
        <font size="7">
          <xsl:value-of select="substring-before(cdf:plain-text,'Benchmark Date:')"/>
        </font>
      </b>
      <br/>
    </p>
    <p align="center">
      <b>
        <font size="7">
          <xsl:value-of select="substring-after(cdf:plain-text,'Benchmark Date:')"/>
        </font>
      </b>
      <br/>
    </p>
    <br/>
    <br/>
    <br/>
    <br/>
    <br/>
    <font size="5">
      <b>XSL Release 11/7/2019 &#160;&#160;&#160;  Sort by: &#160; STIGID</b>
    </font>
    <br/>
    <font size="5">
      <b>Description:</b>&#160;<xsl:value-of select="cdf:description"/>
    </font>
    <br/>
    <xsl:if test="string-length(cdf:front-matter) &gt; 0">
      <b>Benchmark front matter</b>:&#160;<br/>
      <xsl:call-template name="text-format">
        <xsl:with-param name="text2format" select="cdf:front-matter"/>
      </xsl:call-template>
      <br/>
    </xsl:if>
    <br/>
    <xsl:if test="string-length(cdf:rear-matter) &gt; 0">
      <b>Benchmark rear matter</b>:&#160;<br/>
      <xsl:call-template name="text-format">
        <xsl:with-param name="text2format" select="cdf:rear-matter"/>
      </xsl:call-template>
      <br/>
    </xsl:if>
    <br/>
    <hr/>
    <br/>
    <xsl:for-each select="cdf:Group">
      <xsl:sort data-type="text" select="cdf:Rule/cdf:version"/>
      <xsl:apply-templates select="."/>
      <xsl:for-each select="cdf:Rule">
        <xsl:apply-templates select="."/>
        <xsl:for-each select="cdf:ident[@system='http://iase.disa.mil/cci']">
          <br/>
          <xsl:apply-templates select="."/>
        </xsl:for-each>
        <xsl:for-each select="cdf:ident[@system='http://cyber.mil/cci']">
          <br/>
          <xsl:apply-templates select="."/>
        </xsl:for-each>
        <hr/>
        <br/>
        <br/>
      </xsl:for-each>
    </xsl:for-each>
    <br/>
    <br/>
    <p align="center">
      <b>
        <font size="7">UNCLASSIFIED</font>
      </b>
      <br/>
    </p>
  </xsl:template>
  <xsl:template match="cdf:Group">
    <font size="5">
      <b>Group ID (Vulid):&#160;</b>
    </font>
    <font size="5" color="black">
      <xsl:value-of select="@id"/>
    </font>
    <br/>
    <font size="5">
      <b>Group Title:&#160;</b>
    </font>
    <font size="5" color="black">
      <xsl:value-of select="cdf:title"/>
    </font>
    <br/>
  </xsl:template>
  <xsl:template match="cdf:Rule">
    <font size="5">
      <b>Rule ID:&#160;</b>
    </font>
    <font size="5" color="black">
      <xsl:value-of select="@id"/>
    </font>
    <br/>
    <xsl:if test="@severity='high' ">
      <font size="5">
        <b>Severity: CAT I</b>
        <br/>
      </font>
    </xsl:if>
    <xsl:if test="@severity='medium' ">
      <font size="5">
        <b>Severity: CAT II</b>
        <br/>
      </font>
    </xsl:if>
    <xsl:if test="@severity='low' ">
      <font size="5">
        <b>Severity: CAT III</b>
        <br/>
      </font>
    </xsl:if>
    <font size="5">
      <b>Rule Version (STIG-ID):&#160;</b>
    </font>
    <font size="5" color="blue">
      <xsl:value-of select="cdf:version"/>
    </font>
    <br/>
    <font size="5">
      <b>Rule Title:&#160;</b>
      <xsl:value-of select="cdf:title"/>
    </font>
    <br/>
    <xsl:for-each select="cdf:ident[@system='http://cyber.mil/legacy']">
      <xsl:apply-templates select="."/>
    </xsl:for-each>
    <br/>
    <br/>
    <xsl:apply-templates select="cdf:description"/>
    <xsl:apply-templates select="cdf:check"/>
    <xsl:apply-templates select="cdf:fixtext"/>
    <xsl:apply-templates select="cdf:fix"/>
   &#160;

	</xsl:template>
  <xsl:template match="cdf:ident">
    <font size="5">
      <xsl:if test="./@system='http://iase.disa.mil/cci' or ./@system='http://cyber.mil/cci'">
      <br/>
        <b>CCI:&#160;</b>
      </xsl:if>
      <xsl:if test="./@system='http://cyber.mil/legacy'">
        <b>Legacy ID:&#160;</b>
      </xsl:if>
      <xsl:value-of select="."/>
    </font>
    <br/>
  </xsl:template>
  <xsl:template match="cdf:fixtext">
    <br/>
    <xsl:if test="string-length(.)>0">
      <font size="5">
        <b>Fix Text:&#160;</b>
        <xsl:call-template name="text-format">
          <xsl:with-param name="text2format" select="."/>
        </xsl:call-template>
      </font>
    </xsl:if>
  </xsl:template>
  <xsl:template match="cdf:fix">
  </xsl:template>
  <xsl:template match="cdf:check">
    <xsl:if test="not(substring(@system,1,11)='http://oval') ">
      <br/>
      <xsl:apply-templates select="cdf:check-content-ref"/>
      <xsl:apply-templates select="cdf:check-content"/>
    </xsl:if>
  </xsl:template>
  <xsl:template match="@href">
    <font size="5">
      <b>Check Content Ref Href:&#160;</b>
    </font>
    <font size="5">
      <xsl:value-of select="."/>
    </font>
  </xsl:template>
  <xsl:template match="cdf:check-content">
    <font size="5">
      <b>Check Content:</b>&#160;   <br/>
      <xsl:call-template name="text-format">
        <xsl:with-param name="text2format" select="."/>
      </xsl:call-template>
      <br/>
    </font>
  </xsl:template>
  <xsl:template match="cdf:description">
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/VulnDiscussion&gt;'), '&lt;VulnDiscussion&gt;'))>0">
      <font size="5">
        <b>Vulnerability Discussion:</b>&#160;</font>
      <font size="5">
        <xsl:call-template name="text-format">
          <xsl:with-param name="text2format" select="substring-after(substring-before(.,'&lt;/VulnDiscussion&gt;'), '&lt;VulnDiscussion&gt;')"/>
        </xsl:call-template>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/FalsePositives&gt;'), '&lt;FalsePositives&gt;'))>0">
      <font size="5">
        <b>False Positives:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/FalsePositives&gt;'), '&lt;FalsePositives&gt;')"/>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/FalseNegatives&gt;'), '&lt;FalseNegatives&gt;'))>0">
      <font size="5">
        <b>False Negatives:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/FalseNegatives&gt;'), '&lt;FalseNegatives&gt;')"/>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/Mitigations&gt;'), '&lt;Mitigations&gt;'))>0">
      <font size="5">
        <b>Mitigations:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/Mitigations&gt;'), '&lt;Mitigations&gt;')"/>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/SecurityOverrideGuidance&gt;'), '&lt;SecurityOverrideGuidance&gt;'))>0">
      <font size="5">
        <b>Severity Override Guidance:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:call-template name="text-format">
          <xsl:with-param name="text2format" select="substring-after(substring-before(.,'&lt;/SecurityOverrideGuidance&gt;'), '&lt;SecurityOverrideGuidance&gt;')"/>
        </xsl:call-template>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/SeverityOverrideGuidance&gt;'), '&lt;SeverityOverrideGuidance&gt;'))>0">
      <font size="5">
        <b>Severity Override Guidance:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:call-template name="text-format">
          <xsl:with-param name="text2format" select="substring-after(substring-before(.,'&lt;/SeverityOverrideGuidance&gt;'), '&lt;SeverityOverrideGuidance&gt;')"/>
        </xsl:call-template>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/PotentialImpacts&gt;'), '&lt;PotentialImpacts&gt;'))>0">
      <font size="5">
        <b>Potential Impacts:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/PotentialImpacts&gt;'), '&lt;PotentialImpacts&gt;')"/>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/MitigationControl&gt;'), '&lt;MitigationControl&gt;'))>1">
      <font size="5">
        <b>Mitigation Control:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:call-template name="text-format">
          <xsl:with-param name="text2format" select="substring-after(substring-before(.,'&lt;/MitigationControl&gt;'), '&lt;MitigationControl&gt;')"/>
        </xsl:call-template>
      </font>
      <br/>
      <br/>
    </xsl:if>
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/IAControls&gt;'), '&lt;IAControls&gt;'))>0">
      <font size="5">
        <b>IAControls:</b>&#160;</font>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/IAControls&gt;'), '&lt;IAControls&gt;')"/>
      </font>
      <br/>
    </xsl:if>
  </xsl:template>
  <xsl:template match="cdf:group/cdf:description">
    <xsl:if test="string-length(substring-after(substring-before(.,'&lt;/GroupDescription&gt;'), '&lt;GroupDescription&gt;'))>0">
      <font size="5">
        <b>Group Discussion:</b>&#160;</font>
      <br/>
      <font size="5">
        <xsl:value-of select="substring-after(substring-before(.,'&lt;/GroupDescription&gt;'), '&lt;GroupDescription&gt;')"/>
      </font>
      <br/>
    </xsl:if>
  </xsl:template>
  <xsl:template name="text-format">
    <xsl:param name="text2format"/>
    <xsl:if test="string-length($text2format) &lt;= 1">
      <xsl:choose>
        <xsl:when test="$text2format = '&#xA;'">
          <!-- newline to <br/> -->
          <br/>
        </xsl:when>
        <xsl:when test="$text2format = '&#x9;'">
          <!-- tab to five spaces -->
					&#160;&#160;&#160;&#160;&#160;
				</xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$text2format"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
    <xsl:if test="string-length($text2format) &gt; 1">
      <xsl:variable name="mid" select="floor(string-length($text2format) div 2)"/>
      <xsl:call-template name="text-format">
        <xsl:with-param name="text2format" select="substring($text2format, 1, $mid)"/>
      </xsl:call-template>
      <xsl:call-template name="text-format">
        <xsl:with-param name="text2format" select="substring($text2format, $mid + 1, string-length($text2format))"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
