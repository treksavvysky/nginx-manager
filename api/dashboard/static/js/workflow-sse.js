/**
 * Workflow SSE Progress Client.
 *
 * Uses fetch() with ReadableStream to consume SSE from a POST endpoint.
 */
/* exported startWorkflow */
function startWorkflow(formId, progressId, resultId) {
  var form = document.getElementById(formId);
  var progress = document.getElementById(progressId);
  var result = document.getElementById(resultId);
  if (!form) return;

  // Collect form data into plain object
  var fd = new FormData(form);
  var data = {};
  fd.forEach(function (v, k) {
    data[k] = v;
  });

  // Checkboxes: present means "on", map to boolean
  form.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
    data[cb.name] = cb.checked;
  });

  var workflowType = data.workflow_type || "setup-site";
  delete data.workflow_type;

  // server_names: comma-separated → array
  if (typeof data.server_names === "string" && data.server_names.trim()) {
    data.server_names = data.server_names
      .split(",")
      .map(function (s) {
        return s.trim();
      })
      .filter(Boolean);
  } else {
    data.server_names = data.name ? [data.name] : [];
  }

  // listen_port to int
  if (data.listen_port) {
    data.listen_port = parseInt(data.listen_port, 10) || 80;
  }

  // Strip empty optional strings
  ["root_path", "proxy_pass"].forEach(function (key) {
    if (!data[key] || !data[key].trim()) delete data[key];
  });

  // Disable form
  form
    .querySelectorAll("button, input, select, textarea")
    .forEach(function (el) {
      el.disabled = true;
    });

  progress.innerHTML =
    '<div class="workflow-progress"><p>Starting workflow...</p></div>';
  progress.style.display = "block";
  result.innerHTML = "";

  fetch("/dashboard/workflows/" + workflowType + "/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
    .then(function (response) {
      if (!response.ok) {
        return response.text().then(function (text) {
          throw new Error(text || "Workflow failed to start");
        });
      }
      return response;
    })
    .then(function (response) {
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";

      function processChunk(text) {
        buffer += text;
        var parts = buffer.split("\n\n");
        buffer = parts.pop(); // incomplete event stays in buffer

        parts.forEach(function (part) {
          var eventType = "";
          var eventData = "";
          part.split("\n").forEach(function (line) {
            if (line.indexOf("event: ") === 0) eventType = line.substring(7);
            else if (line.indexOf("data: ") === 0)
              eventData = line.substring(6);
          });
          if (eventType && eventData) {
            try {
              handleEvent(eventType, JSON.parse(eventData));
            } catch (_e) {
              /* skip malformed */
            }
          }
        });
      }

      function handleEvent(type, evt) {
        if (type === "workflow_started") {
          progress.innerHTML =
            '<div class="workflow-progress"><h3>Workflow in progress...</h3><div id="wf-steps"></div></div>';
        } else if (type === "step_started") {
          appendStep(evt.step_number, evt.total_steps, evt.message, "running");
        } else if (type === "step_completed") {
          updateStep(evt.step_number, evt.message, "completed");
        } else if (type === "step_failed") {
          updateStep(evt.step_number, evt.message, "failed");
        } else if (type === "step_skipped") {
          appendStep(
            evt.step_number,
            evt.total_steps,
            evt.message,
            "skipped",
          );
        } else if (type === "result") {
          showResult(evt);
        }
      }

      function appendStep(num, total, msg, status) {
        var steps = document.getElementById("wf-steps");
        if (!steps) return;
        var el = document.getElementById("wf-step-" + num);
        if (el) {
          el.className = "workflow-step " + status;
          el.querySelector(".step-info span").textContent = msg;
          return;
        }
        var div = document.createElement("div");
        div.id = "wf-step-" + num;
        div.className = "workflow-step " + status;
        div.innerHTML =
          '<div class="step-icon"></div><div class="step-info"><strong>Step ' +
          num +
          "/" +
          total +
          "</strong> <span>" +
          escapeHtml(msg) +
          "</span></div>";
        steps.appendChild(div);
      }

      function updateStep(num, msg, status) {
        var el = document.getElementById("wf-step-" + num);
        if (el) {
          el.className = "workflow-step " + status;
          el.querySelector(".step-info span").textContent = msg;
        }
      }

      function showResult(data) {
        var cls =
          data.status === "completed"
            ? "success"
            : data.status === "partially_completed"
              ? "warning"
              : "error";
        var html = '<div class="toast ' + cls + '">';
        html += "<strong>" + escapeHtml(data.message) + "</strong>";
        if (data.transaction_ids && data.transaction_ids.length) {
          html +=
            "<br><small>Transactions: " +
            data.transaction_ids
              .map(function (id) {
                return id.substring(0, 8);
              })
              .join(", ") +
            "</small>";
        }
        if (data.warnings && data.warnings.length) {
          data.warnings.forEach(function (w) {
            html +=
              '<br><small style="color: var(--color-warning);">' +
              escapeHtml(w.message || String(w)) +
              "</small>";
          });
        }
        html += "</div>";
        result.innerHTML = html;
        enableForm();
      }

      function enableForm() {
        form
          .querySelectorAll("button, input, select, textarea")
          .forEach(function (el) {
            el.disabled = false;
          });
      }

      function escapeHtml(s) {
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
      }

      function read() {
        reader.read().then(function (chunk) {
          if (chunk.done) {
            // Process any remaining buffer
            if (buffer.trim()) processChunk("\n\n");
            enableForm();
            return;
          }
          processChunk(decoder.decode(chunk.value, { stream: true }));
          read();
        });
      }

      read();
    })
    .catch(function (err) {
      progress.innerHTML =
        '<div class="toast error">' + (err.message || "Unknown error") + "</div>";
      form
        .querySelectorAll("button, input, select, textarea")
        .forEach(function (el) {
          el.disabled = false;
        });
    });
}
