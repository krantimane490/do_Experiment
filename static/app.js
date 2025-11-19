document.addEventListener("DOMContentLoaded", () => {
    const registerForm = document.getElementById("register-form");
    const loginForm = document.getElementById("login-form");
    const createTaskForm = document.getElementById("create-task-form");
    const getTasksBtn = document.getElementById("get-tasks-btn");
    const tasksContainer = document.getElementById("tasks-container");
    const deleteTaskBtn = document.getElementById("delete-task-btn");

    const showToast = (message, type = "success") => {
        Toastify({
            text: message,
            duration: 3000,
            close: true,
            gravity: "top", // `top` or `bottom`
            position: "right", // `left`, `center` or `right`
            backgroundColor: type === "success" ? "linear-gradient(to right, #00b09b, #96c93d)" : "linear-gradient(to right, #ff5f6d, #ffc371)",
        }).showToast();
    };

    if (registerForm) {
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const email = document.getElementById("register-email").value;
            const password = document.getElementById("register-password").value;

            try {
                const response = await fetch("/register", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ email, password }),
                });

                const data = await response.json();
                if (response.ok) {
                    showToast("Registration successful!");
                } else {
                    showToast(data.message || "Registration failed.", "error");
                }
            } catch (error) {
                showToast("Registration error.", "error");
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const email = document.getElementById("login-email").value;
            const password = document.getElementById("login-password").value;

            try {
                const response = await fetch("/login", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ email, password }),
                });

                const data = await response.json();
                if (response.ok) {
                    showToast("Login successful!");
                } else {
                    showToast(data.message || "Login failed.", "error");
                }
            } catch (error) {
                showToast("Login error.", "error");
            }
        });
    }

    if (createTaskForm) {
        createTaskForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const title = document.getElementById("task-title").value;
            const description = document.getElementById("task-description").value;
            const due_date = document.getElementById("task-due-date").value;

            try {
                const response = await fetch("/tasks", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ title, description, due_date }),
                });

                const data = await response.json();
                if (response.ok) {
                    showToast("Task created successfully!");
                    // Clear form fields
                    document.getElementById("task-title").value = "";
                    document.getElementById("task-description").value = "";
                    document.getElementById("task-due-date").value = "";

                    // Refresh task list
                    getTasksBtn.click();
                } else {
                    showToast(data.message || "Failed to create task.", "error");
                }
            } catch (error) {
                showToast("Create task error.", "error");
            }
        });
    }

    if (getTasksBtn) {
        getTasksBtn.addEventListener("click", async () => {
            try {
                const response = await fetch("/tasks");
                const tasks = await response.json();

                tasksContainer.innerHTML = ""; // Clear previous tasks

                tasks.forEach(task => {
                    const taskElement = document.createElement("div");
                    taskElement.innerHTML = `
                        <h3><a href="/tasks/${task.id}">${task.title}</a></h3>
                        <p>${task.description}</p>
                        <p>Due: ${task.due_date}</p>
                        <p>Completed: ${task.completed}</p>
                    `;
                    tasksContainer.appendChild(taskElement);
                });
            } catch (error) {
                showToast("Get tasks error.", "error");
            }
        });
    }

    if (deleteTaskBtn) {
        deleteTaskBtn.addEventListener("click", async () => {
            const taskId = deleteTaskBtn.getAttribute("data-task-id");
            if (confirm("Are you sure you want to delete this task?")) {
                try {
                    const response = await fetch(`/tasks/${taskId}`, {
                        method: "DELETE",
                    });

                    const data = await response.json();
                    if (response.ok) {
                        showToast("Task deleted successfully!");
                        window.location.href = "/";
                    } else {
                        showToast(data.message || "Failed to delete task.", "error");
                    }
                } catch (error) {
                    showToast("Delete task error.", "error");
                }
            }
        });
    }
});