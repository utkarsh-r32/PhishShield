/**
 * PhishShield Gmail Add-on
 * MVP version
 */

const PHISHSHIELD_API =
  'https://phishshield-app.onrender.com';


/**
 * Homepage card
 */
function buildHomeCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('PhishShield')
        .setSubtitle('Phishing Email Protection')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Protect your inbox from phishing.</b><br>' +
              'Open an email and use PhishShield to analyze it.'
            )
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Open PhishShield')
            .setOpenLink(
              CardService.newOpenLink()
                .setUrl(PHISHSHIELD_API)
                .setOpenAs(CardService.OpenAs.FULL_SIZE)
                .setOnClose(CardService.OnClose.NOTHING)
            )
        )
    )
    .build();
}


/**
 * Card displayed when a Gmail message is opened.
 */
function buildGmailCard(e) {

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('PhishShield')
        .setSubtitle('Email Security Analysis')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Suspicious email?</b><br>' +
              'Analyze the currently opened email with PhishShield.'
            )
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Analyze with PhishShield')
            .setTextButtonStyle(
              CardService.TextButtonStyle.FILLED
            )
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName('analyzeCurrentEmail')
            )
        )
    )
    .build();
}


/**
 * Analyze the currently opened Gmail message.
 */
function analyzeCurrentEmail(e) {

  try {

    if (!e || !e.gmail || !e.gmail.messageId) {
      return createErrorCard(
        'Unable to access the current Gmail message.'
      );
    }

    const messageId = e.gmail.messageId;
    const accessToken = e.gmail.accessToken;

    if (!accessToken) {
      return createErrorCard(
        'Gmail did not provide a message access token.'
      );
    }

    // Give GmailApp temporary permission to access
    // only the current message.
    GmailApp.setCurrentMessageAccessToken(accessToken);

    const message =
      GmailApp.getMessageById(messageId);

    if (!message) {
      return createErrorCard(
        'The current Gmail message could not be found.'
      );
    }

    const sender = message.getFrom();
    const recipient = message.getTo();
    const cc = message.getCc();
    const subject = message.getSubject();
    const date = message.getDate();
    const body = message.getPlainBody();

    const payload = {
      provider: 'gmail',

      message: {
        from: sender,
        to: recipient,
        cc: cc,
        subject: subject,
        date: date.toISOString(),
        body: body
      }
    };

    return sendToPhishShield(payload);

  } catch (error) {

    console.error(error);

    return createErrorCard(
      'Analysis failed: ' + error.message
    );
  }
}


/**
 * Send the normalized email to PhishShield.
 *
 * This function will be connected to the
 * authenticated PhishShield API in the next step.
 */
function sendToPhishShield(payload) {

  try {

    const response = UrlFetchApp.fetch(
      PHISHSHIELD_API + '/api/v1/analyze-gmail',
      {
        method: 'post',

        contentType: 'application/json',

        payload: JSON.stringify(payload),

        muteHttpExceptions: true
      }
    );

    const status =
      response.getResponseCode();

    const text =
      response.getContentText();

    if (status < 200 || status >= 300) {

      console.error(
        'PhishShield API error:',
        status,
        text
      );

      return createErrorCard(
        'PhishShield server returned HTTP ' + status
      );
    }

    const result =
      JSON.parse(text);

    return createResultCard(result);

  } catch (error) {

    console.error(error);

    return createErrorCard(
      'Could not connect to PhishShield: ' +
      error.message
    );
  }
}


/**
 * Display analysis results.
 */
function createResultCard(result) {

  const score =
    result.score ?? result.riskScore ?? 0;

  const risk =
    result.risk ??
    result.riskLevel ??
    'UNKNOWN';

  const findings =
    result.findings ?? [];

  let findingsText = '';

  if (Array.isArray(findings) && findings.length > 0) {

    findingsText = findings
      .slice(0, 5)
      .map(function(item) {

        if (typeof item === 'string') {
          return '• ' + item;
        }

        return '• ' +
          (item.description ||
           item.message ||
           item.reason ||
           JSON.stringify(item));

      })
      .join('<br>');

  } else {

    findingsText =
      'No individual findings were returned.';
  }


  return CardService.newCardBuilder()

    .setHeader(
      CardService.newCardHeader()
        .setTitle('PhishShield Result')
        .setSubtitle('Email Security Analysis')
    )

    .addSection(

      CardService.newCardSection()

        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Risk Level</b><br>' +
              '<font size="large">' +
              risk +
              '</font>'
            )
        )

        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Risk Score</b><br>' +
              score +
              ' / 100'
            )
        )

        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Key Findings</b><br>' +
              findingsText
            )
        )
    )

    .addSection(

      CardService.newCardSection()

        .addWidget(
          CardService.newTextButton()
            .setText('View Full Investigation')
            .setOpenLink(
              CardService.newOpenLink()
                .setUrl(PHISHSHIELD_API)
                .setOpenAs(
                  CardService.OpenAs.FULL_SIZE
                )
                .setOnClose(
                  CardService.OnClose.NOTHING
                )
            )
        )
    )

    .build();
}


/**
 * Display an error inside Gmail.
 */
function createErrorCard(message) {

  return CardService.newCardBuilder()

    .setHeader(
      CardService.newCardHeader()
        .setTitle('PhishShield')
        .setSubtitle('Analysis Error')
    )

    .addSection(

      CardService.newCardSection()

        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '<b>Something went wrong.</b><br><br>' +
              escapeHtml(message)
            )
        )
    )

    .build();
}


/**
 * Basic HTML escaping.
 */
function escapeHtml(value) {

  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}