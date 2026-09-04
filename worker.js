const DEFAULT_DATA = {

  hero: {
    title:
      "Training that sees the person behind every case.",

    text:
      "The Aegis Institute supports Discord communities and individuals through personalised consulting and structured education — built around your rules, your people, and your goals.",

    cardTitle:
      "Two branches. One standard of care.",

    cardText:
      "Consulting for communities that want clarity — education for staff and aspiring moderators who want to know where to start."
  },

  services: [
    {
      label: "SERVER OWNERS",

      title:
        "Outsourced staff training",

      description:
        "High-quality training, assessments and feedback aligned to your rules and procedures.",

      bullets: [
        "Training, assessments & educator support",
        "Structured standards",
        "Actionable feedback"
      ]
    },

    {
      label: "PLAYERS",

      title:
        "Moderator & Advanced Fundamentals",

      description:
        "Preparation for aspiring moderators and supervisors who want to build practical skills.",

      bullets: [
        "Moderator fundamentals",
        "Advanced fundamentals",
        "Practical scenarios"
      ]
    }
  ],

  work: [
    {
      label: "STAFF DEVELOPMENT",

      title:
        "Structured staff programmes",

      description:
        "Clear pathways for trainees, moderators, supervisors and leadership teams."
    },

    {
      label: "STANDARDS",

      title:
        "Policies that people can actually use",

      description:
        "Practical policies, procedures and expectations written around the way your community operates."
    },

    {
      label: "CONSULTING",

      title:
        "An external perspective",

      description:
        "Honest feedback on systems, staff structures, training and community operations."
    },

    {
      label: "EDUCATION",

      title:
        "Training built around scenarios",

      description:
        "Learn through examples and situations that staff can actually encounter."
    }
  ],

  contact: {
    title:
      "Let's talk about what your community needs.",

    text:
      "Have a question, project idea, or training requirement? Send a message and the Aegis team can help."
  }

};


/* ==================================
   MAIN WORKER
================================== */

export default {

  async fetch(request, env) {

    const url =
      new URL(request.url);


    /* ------------------------------
       AUTH
    ------------------------------ */

    if (
      url.pathname ===
      "/api/auth/discord"
    ) {

      return startDiscordLogin(
        env
      );

    }


    if (
      url.pathname ===
      "/api/auth/callback"
    ) {

      return discordCallback(
        request,
        env
      );

    }


    if (
      url.pathname ===
      "/api/auth/me"
    ) {

      return getMe(
        request,
        env
      );

    }


    if (
      url.pathname ===
      "/api/auth/logout"
    ) {

      return logout();

    }


    /* ------------------------------
       CONTENT
    ------------------------------ */

    if (
      url.pathname ===
      "/api/content"
    ) {

      if (
        request.method === "GET"
      ) {

        return getContent(
          env
        );

      }


      if (
        request.method === "PUT"
      ) {

        return saveContent(
          request,
          env
        );

      }

    }


    /* ------------------------------
       STATIC WEBSITE
    ------------------------------ */

    return env.ASSETS.fetch(
      request
    );

  }

};


/* ==================================
   DISCORD LOGIN
================================== */

function startDiscordLogin(env) {

  const state =
    crypto.randomUUID();


  const params =
    new URLSearchParams({

      client_id:
        env.DISCORD_CLIENT_ID,

      response_type:
        "code",

      redirect_uri:
        env.DISCORD_REDIRECT_URI,

      scope:
        "identify guilds.members.read",

      state

    });


  return new Response(
    null,
    {
      status: 302,

      headers: {

        "Location":
          "https://discord.com/oauth2/authorize?" +
          params.toString(),

        "Set-Cookie":
          `aegis_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`

      }
    }
  );

}


/* ==================================
   DISCORD CALLBACK
================================== */

async function discordCallback(
  request,
  env
) {

  const url =
    new URL(request.url);


  const code =
    url.searchParams.get(
      "code"
    );


  const returnedState =
    url.searchParams.get(
      "state"
    );


  const cookies =
    request.headers.get(
      "Cookie"
    ) || "";


  const stateCookie =
    getCookie(
      cookies,
      "aegis_oauth_state"
    );


  if (
    !code ||
    !returnedState ||
    !stateCookie ||
    returnedState !== stateCookie
  ) {

    return new Response(
      "Invalid OAuth state.",
      {
        status: 400
      }
    );

  }


  try {

    const accessToken =
      await exchangeCode(
        code,
        env
      );


    const user =
      await discordGet(
        "https://discord.com/api/users/@me",
        accessToken
      );


    const member =
      await discordGet(
        `https://discord.com/api/users/@me/guilds/${env.DISCORD_GUILD_ID}/member`,
        accessToken
      );


    const roles =
      member.roles || [];


    const allowedRoles =
      String(
        env.AUTHORIZED_ROLE_IDS || ""
      )
        .split(",")
        .map(x => x.trim())
        .filter(Boolean);


    const authorized =
      roles.some(
        role =>
          allowedRoles.includes(
            role
          )
      );


    const payload = {

      userId:
        user.id,

      username:
        user.global_name ||
        user.username,

      authorized,

      exp:
        Date.now() +
        8 * 60 * 60 * 1000

    };


    const session =
      await signSession(
        payload,
        env.SESSION_SECRET
      );


    const destination =
      authorized
        ? "/admin.html"
        : "/";


    return new Response(
      null,
      {

        status: 302,

        headers: {

          "Location":
            destination,

          "Set-Cookie": [

            `aegis_session=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`,

            "aegis_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"

          ]

        }

      }
    );


  } catch (error) {

    return new Response(
      "Discord login failed: " +
      error.message,
      {
        status: 500
      }
    );

  }

}


/* ==================================
   TOKEN EXCHANGE
================================== */

async function exchangeCode(
  code,
  env
) {

  const body =
    new URLSearchParams({

      client_id:
        env.DISCORD_CLIENT_ID,

      client_secret:
        env.DISCORD_CLIENT_SECRET,

      grant_type:
        "authorization_code",

      code,

      redirect_uri:
        env.DISCORD_REDIRECT_URI

    });


  const response =
    await fetch(
      "https://discord.com/api/oauth2/token",
      {

        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body

      }
    );


  if (!response.ok) {

    throw new Error(
      "Discord token exchange failed."
    );

  }


  const data =
    await response.json();


  return data.access_token;

}


/* ==================================
   DISCORD API
================================== */

async function discordGet(
  url,
  token
) {

  const response =
    await fetch(
      url,
      {

        headers: {
          Authorization:
            `Bearer ${token}`
        }

      }
    );


  if (!response.ok) {

    throw new Error(
      "Discord API request failed."
    );

  }


  return response.json();

}


/* ==================================
   ME
================================== */

async function getMe(
  request,
  env
) {

  const token =
    getCookie(
      request.headers.get(
        "Cookie"
      ) || "",
      "aegis_session"
    );


  if (!token) {

    return json({
      authenticated: false,
      authorized: false
    });

  }


  const payload =
    await verifySession(
      token,
      env.SESSION_SECRET
    );


  if (!payload) {

    return json({
      authenticated: false,
      authorized: false
    });

  }


  return json({

    authenticated: true,

    authorized:
      !!payload.authorized,

    username:
      payload.username,

    userId:
      payload.userId

  });

}


/* ==================================
   CONTENT GET
================================== */

async function getContent(
  env
) {

  if (!env.DB) {

    return json(
      DEFAULT_DATA
    );

  }


  const row =
    await env.DB
      .prepare(
        "SELECT value FROM portal_content WHERE id = 'main'"
      )
      .first();


  if (!row) {

    return json(
      DEFAULT_DATA
    );

  }


  try {

    return json(
      JSON.parse(
        row.value
      )
    );

  } catch {

    return json(
      DEFAULT_DATA
    );

  }

}


/* ==================================
   CONTENT SAVE
================================== */

async function saveContent(
  request,
  env
) {

  const session =
    await getSession(
      request,
      env
    );


  if (
    !session ||
    !session.authorized
  ) {

    return json(
      {
        error:
          "You are not authorised to edit this website."
      },
      403
    );

  }


  if (!env.DB) {

    return json(
      {
        error:
          "D1 is not configured."
      },
      500
    );

  }


  const data =
    await request.json();


  await env.DB
    .prepare(
      `INSERT INTO portal_content
       (id, value, updated_at)
       VALUES ('main', ?, ?)
       ON CONFLICT(id)
       DO UPDATE SET
       value = excluded.value,
       updated_at = excluded.updated_at`
    )
    .bind(
      "main",
      JSON.stringify(data),
      new Date().toISOString()
    )
    .run();


  return json({
    ok: true
  });

}


/* ==================================
   SESSION
================================== */

async function getSession(
  request,
  env
) {

  const token =
    getCookie(
      request.headers.get(
        "Cookie"
      ) || "",
      "aegis_session"
    );


  if (!token)
    return null;


  return verifySession(
    token,
    env.SESSION_SECRET
  );

}


async function signSession(
  payload,
  secret
) {

  const encoded =
    base64url(
      new TextEncoder().encode(
        JSON.stringify(
          payload
        )
      )
    );


  const key =
    await crypto.subtle.importKey(
      "raw",

      new TextEncoder().encode(
        secret
      ),

      {
        name: "HMAC",
        hash: "SHA-256"
      },

      false,

      ["sign"]
    );


  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(
        encoded
      )
    );


  return (
    encoded +
    "." +
    base64url(
      new Uint8Array(
        signature
      )
    )
  );

}


async function verifySession(
  token,
  secret
) {

  try {

    const parts =
      token.split(".");


    if (parts.length !== 2)
      return null;


    const payloadPart =
      parts[0];

    const signaturePart =
      parts[1];


    const key =
      await crypto.subtle.importKey(
        "raw",

        new TextEncoder().encode(
          secret
        ),

        {
          name: "HMAC",
          hash: "SHA-256"
        },

        false,

        ["verify"]
      );


    const valid =
      await crypto.subtle.verify(
        "HMAC",

        key,

        fromBase64url(
          signaturePart
        ),

        new TextEncoder().encode(
          payloadPart
        )
      );


    if (!valid)
      return null;


    const payload =
      JSON.parse(
        new TextDecoder().decode(
          fromBase64url(
            payloadPart
          )
        )
      );


    if (
      !payload.exp ||
      payload.exp < Date.now()
    ) {

      return null;

    }


    return payload;

  } catch {

    return null;

  }

}


/* ==================================
   LOGOUT
================================== */

function logout() {

  return new Response(
    JSON.stringify({
      ok: true
    }),
    {

      headers: {

        "Content-Type":
          "application/json",

        "Set-Cookie":
          "aegis_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"

      }

    }
  );

}


/* ==================================
   HELPERS
================================== */

function getCookie(
  cookieString,
  name
) {

  const found =
    cookieString
      .split(";")
      .map(x => x.trim())
      .find(
        x =>
          x.startsWith(
            name + "="
          )
      );


  return found
    ? found.slice(
        name.length + 1
      )
    : null;

}


function base64url(
  bytes
) {

  let binary = "";

  for (
    const byte of bytes
  ) {

    binary += String.fromCharCode(
      byte
    );

  }


  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

}


function fromBase64url(
  value
) {

  const base64 =
    value
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(
        Math.ceil(
          value.length / 4
        ) * 4,
        "="
      );


  const binary =
    atob(base64);


  const bytes =
    new Uint8Array(
      binary.length
    );


  for (
    let i = 0;
    i < binary.length;
    i++
  ) {

    bytes[i] =
      binary.charCodeAt(i);

  }


  return bytes;

}


function json(
  data,
  status = 200
) {

  return new Response(
    JSON.stringify(data),
    {

      status,

      headers: {
        "Content-Type":
          "application/json"
      }

    }
  );

}
